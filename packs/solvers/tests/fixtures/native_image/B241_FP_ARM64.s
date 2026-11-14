    .text
start:
f_add:                          // (F, F) -> F
    fadd s0, s0, s1
    ret
    .balign 16
d_mul:                          // (D, D) -> D
    fmul d0, d0, d1
    ret
    .balign 16
mix:                            // (I a, F x, J b, D y) -> D = a + x + b + y
    scvtf d2, w2
    fcvt d0, s0
    fadd d0, d0, d2
    scvtf d2, x3
    fadd d0, d0, d2
    fadd d0, d0, d1
    ret
    .balign 16
f_to_int:                       // (F) -> I, truncating
    fcvtzs w0, s0
    ret
    .balign 16
int_to_f:                       // (I) -> F
    scvtf s0, w2
    ret
    .balign 16
f_upper:                        // bits 32..63 of the first vector register
    mov s0, v0.s[1]
    ret
    .balign 16
d_upper:                        // bits 64..127 of the first vector register
    mov d0, v0.d[1]
    ret
    .balign 16
f_unset:                        // a vector register no argument was passed in
    fmov s0, s3
    ret
    .balign 16
f_nan:                          // 0.0 / 0.0
    movi d0, #0
    fdiv s0, s0, s0
    ret
    .balign 16
f_inf:                          // x / 0.0
    movi d1, #0
    fdiv s0, s0, s1
    ret
