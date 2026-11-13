    .intel_syntax noprefix
    .text
    .set BASE, 0x401000
    .set IAT0, 0x402100
    .set IAT1, 0x402104
    .set IAT2, 0x402108
    .set IAT3, 0x40210C
    .set IAT4, 0x402110
    .set IAT5, 0x402114
    .set DIAT0, 0x402180
    .set D_CODE, 0x403000
    .set D_ADDR, 0x403004
    .set D_FLAGS, 0x403008
    .set D_CTXFL, 0x40300C
    .set D_SKIP, 0x403010
    .set D_COUNT, 0x403014
    .set D_DISP, 0x403018
    .set D_NPARAM, 0x40301C
    .set D_INFO0, 0x403020
    .set D_INFO1, 0x403024
    .set D_OUTER, 0x403028
    .set D_VEH, 0x40302C
    .set D_VEHDISP, 0x403030
    .set D_AB, 0x403034
    .set D_FRAME, 0x403038
    .set D_UWRET, 0x40303C
    .set D_INNERFLAGS, 0x403040
    .set D_INNERUNW, 0x403044
    .set D_NREAD, 0x403048
    .set D_NWRIT, 0x40304C
    .set D_OLD, 0x403050
    .set D_TLS, 0x403054
    .set D_BUF, 0x403080
    .set PACKED, 0x404000

start:
# ---- the generic SEH handler: records what it was given, then answers with D_DISP
handler:
    mov edx, dword ptr [esp+4]
    mov ecx, dword ptr [esp+0xC]
    mov eax, dword ptr [edx]
    mov dword ptr [D_CODE], eax
    mov eax, dword ptr [edx+0xC]
    mov dword ptr [D_ADDR], eax
    mov eax, dword ptr [edx+4]
    mov dword ptr [D_FLAGS], eax
    mov eax, dword ptr [ecx+0xC0]
    mov dword ptr [D_CTXFL], eax
    mov eax, dword ptr [edx+0x10]
    mov dword ptr [D_NPARAM], eax
    test eax, eax
    jz handler_noinfo
    mov eax, dword ptr [edx+0x14]
    mov dword ptr [D_INFO0], eax
    mov eax, dword ptr [edx+0x18]
    mov dword ptr [D_INFO1], eax
handler_noinfo:
    mov eax, dword ptr [D_SKIP]
    add dword ptr [ecx+0xB8], eax
    mov dword ptr [ecx+0xB0], 0x600D
    inc dword ptr [D_COUNT]
    mov eax, dword ptr [D_DISP]
    ret

    .balign 16, 0x90
# ---- the outer handler of the two-frame test: always continues
handler2:
    mov ecx, dword ptr [esp+0xC]
    mov eax, dword ptr [D_SKIP]
    add dword ptr [ecx+0xB8], eax
    mov dword ptr [ecx+0xB0], 0xBEEF
    inc dword ptr [D_OUTER]
    xor eax, eax
    ret

    .balign 16, 0x90
add2:
    mov eax, dword ptr [esp+4]
    add eax, dword ptr [esp+8]
    ret

    .macro SEHMAIN name, fault:vararg
    .balign 16, 0x90
\name:
    push BASE + (handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    xor eax, eax
    xor ecx, ecx
\name\()_fault:
    \fault
    pop dword ptr fs:[0]
    add esp, 4
    ret
    .endm

    SEHMAIN m_int3, int3
    SEHMAIN m_ud2, ud2
    SEHMAIN m_hlt, hlt
    SEHMAIN m_cli, cli
    SEHMAIN m_div, div ecx
    SEHMAIN m_wnull, mov dword ptr [eax], eax
    SEHMAIN m_rnull, mov eax, dword ptr [eax]

    .balign 16, 0x90
# ---- no handler installed at all
m_bare:
    int3
    ret

    .balign 16, 0x90
# ---- two frames: the inner one is `handler`, the outer one `handler2`
m_two:
    push BASE + (handler2 - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    push BASE + (handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    xor eax, eax
m_two_fault:
    int3
    int3
    pop dword ptr fs:[0]
    add esp, 4
    pop dword ptr fs:[0]
    add esp, 4
    ret

    .balign 16, 0x90
# ---- single step: the instruction after popfd runs with TF set, the trap is reported after it
m_step:
    push BASE + (handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    pushfd
    or dword ptr [esp], 0x100
    popfd
    nop
m_step_after:
    nop
    pop dword ptr fs:[0]
    add esp, 4
    ret

    .balign 16, 0x90
# ---- a vectored handler ahead of the frame-based chain (IAT0 = AddVectoredExceptionHandler)
m_veh:
    push BASE + (veh - start)
    push 1
    call dword ptr [IAT0]
    push BASE + (handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    xor eax, eax
m_veh_fault:
    int3
    pop dword ptr fs:[0]
    add esp, 4
    ret
veh:
    mov edx, dword ptr [esp+4]
    mov ecx, dword ptr [edx+4]
    inc dword ptr [D_VEH]
    mov eax, dword ptr [D_VEHDISP]
    cmp eax, 0
    je veh_out
    inc dword ptr [ecx+0xB8]
    mov dword ptr [ecx+0xB0], 0x7E7
veh_out:
    ret 4

    .balign 16, 0x90
# ---- a handler that never returns to the dispatcher: it resets the stack and the chain head
m_abandon:
    push BASE + (abandon_handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
m_abandon_fault:
    int3
abandon_resume:
    inc dword ptr [D_AB]
    cmp dword ptr [D_AB], 2
    jae abandon_done
    int3
abandon_done:
    pop dword ptr fs:[0]
    add esp, 4
    mov eax, dword ptr [D_AB]
    ret
abandon_handler:
    mov eax, dword ptr [esp+8]
    mov esp, eax
    mov dword ptr fs:[0], eax
    jmp abandon_resume

    .balign 16, 0x90
# ---- an exception raised inside a handler
m_nested:
    push BASE + (nested_handler - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    int3
    pop dword ptr fs:[0]
    add esp, 4
    ret
nested_handler:
    int3
    xor eax, eax
    ret

    .balign 16, 0x90
# ---- RtlUnwind (IAT0): the outer handler unwinds the inner frame and recovers
m_unwind:
    push BASE + (unwind_outer - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    mov dword ptr [D_FRAME], esp
    push BASE + (unwind_inner - start)
    push dword ptr fs:[0]
    mov dword ptr fs:[0], esp
    int3
unwind_recover:
    pop dword ptr fs:[0]
    add esp, 4
    mov eax, dword ptr [D_UWRET]
    ret
unwind_inner:
    mov edx, dword ptr [esp+4]
    mov eax, dword ptr [edx+4]
    test eax, 2
    jz unwind_inner_search
    mov dword ptr [D_INNERFLAGS], eax
    inc dword ptr [D_INNERUNW]
unwind_inner_search:
    mov eax, 1
    ret
unwind_outer:
    mov edx, dword ptr [esp+4]
    test dword ptr [edx+4], 2
    jnz unwind_outer_search
    mov ebx, dword ptr [esp+8]
    push 0x77
    push edx
    push BASE + (unwind_after - start)
    push ebx
    call dword ptr [IAT0]
unwind_after:
    mov dword ptr [D_UWRET], eax
    mov esp, ebx
    jmp unwind_recover
unwind_outer_search:
    mov eax, 1
    ret

    .balign 16, 0x90
peb_debugged:
    mov eax, dword ptr fs:[0x30]
    movzx eax, byte ptr [eax+2]
    ret
    .balign 16, 0x90
teb_self:
    mov eax, dword ptr fs:[0x18]
    ret
    .balign 16, 0x90
peb_ldr:
    mov eax, dword ptr fs:[0x30]
    mov eax, dword ptr [eax+0xC]
    ret

    .balign 16, 0x90
# ---- IAT0 VirtualAlloc, IAT1 SetLastError, IAT2 GetLastError, IAT3 CreateFileA (not modelled)
m_api:
    push 4
    push 0x3000
    push 0x2000
    push 0
    call dword ptr [IAT0]
    mov dword ptr [eax], 0x41424344
    mov ecx, dword ptr [eax]
    mov dword ptr [D_CODE], ecx
    mov dword ptr [D_ADDR], eax
    push 0x57
    call dword ptr [IAT1]
    call dword ptr [IAT2]
    ret
    .balign 16, 0x90
m_denied:
    call dword ptr [IAT3]
    ret
    .balign 16, 0x90
# ---- the same SetLastError through the delay-load IAT slot
m_delay:
    push 0x58
    call dword ptr [DIAT0]
    call dword ptr [IAT2]
    ret

    .balign 16, 0x90
# ---- IAT0 GetStdHandle, IAT1 WriteFile, IAT2 ExitProcess, IAT3 ReadFile, IAT4 lstrlenA,
#      IAT5 GetCommandLineA: read stdin, flip the case bit, write stdout, exit(strlen(command line))
m_io:
    push -10
    call dword ptr [IAT0]
    mov esi, eax
    push 0
    push D_NREAD
    push 16
    push D_BUF
    push esi
    call dword ptr [IAT3]
    mov ecx, dword ptr [D_NREAD]
    mov edi, D_BUF
io_loop:
    test ecx, ecx
    jz io_done
    xor byte ptr [edi], 0x20
    inc edi
    dec ecx
    jmp io_loop
io_done:
    push -11
    call dword ptr [IAT0]
    mov esi, eax
    push 0
    push D_NWRIT
    push dword ptr [D_NREAD]
    push D_BUF
    push esi
    call dword ptr [IAT1]
    call dword ptr [IAT5]
    push eax
    call dword ptr [IAT4]
    push eax
    call dword ptr [IAT2]
    hlt

    .balign 16, 0x90
# ---- IAT0 VirtualProtect: make .text writable, then patch the next instruction's immediate
m_protect:
    push D_OLD
    push 0x40
    push 0x1000
    push BASE
    call dword ptr [IAT0]
    mov byte ptr [BASE + (protect_patch - start) + 1], 0x2A
protect_patch:
    mov eax, 0x11
    ret
    .balign 16, 0x90
m_noprotect:
    mov byte ptr [BASE + (protect_patch - start) + 1], 0x2A
    ret

    .balign 16, 0x90
# ---- a packer stub: decrypt six bytes at PACKED in place, then jump to them
m_stub:
    mov esi, PACKED
    mov ecx, 6
stub_loop:
    xor byte ptr [esi], 0x5A
    inc esi
    dec ecx
    jnz stub_loop
    mov eax, PACKED
    jmp eax

    .balign 16, 0x90
# ---- a TLS callback (stdcall, three arguments): keep the reason
tls_callback:
    mov eax, dword ptr [esp+8]
    mov dword ptr [D_TLS], eax
    ret 0xC
