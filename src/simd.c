/*
 * simd.c - SSE → NEON translation
 *
 * Maps x86 SSE/SSE2 scalar and packed operations to ARM64 NEON instructions.
 * XMM0-XMM15 are mapped to V0-V15 (NEON registers).
 *
 * ARM64 NEON instruction encoding for float operations:
 *   Scalar single (32-bit float):  type=00, using S registers
 *   Scalar double (64-bit float):  type=01, using D registers
 */

#include "simd.h"
#include "debug.h"

/*
 * ARM64 floating-point instruction encodings:
 *
 * FADD (scalar): 0 0 0 11110 type 1 Rm 001 010 Rn Rd
 * FSUB (scalar): 0 0 0 11110 type 1 Rm 001 110 Rn Rd
 * FMUL (scalar): 0 0 0 11110 type 1 Rm 000 010 Rn Rd
 * FDIV (scalar): 0 0 0 11110 type 1 Rm 000 110 Rn Rd
 * FSQRT (scalar):0 0 0 11110 type 1 00000 11 0000 Rn Rd
 * FCMP (scalar): 0 0 0 11110 type 1 Rm 00 1000 Rn 0 0000
 * FMOV (scalar): 0 0 0 11110 type 1 0000 00 10000 Rn Rd
 *
 * type: 00 = single (S), 01 = double (D)
 *
 * NEON bitwise ops (128-bit):
 * EOR (vector):  0 1 1 01110 00 1 Rm 00011 1 Rn Rd  (Q=1 for 128-bit)
 * AND (vector):  0 0 0 01110 00 1 Rm 00011 1 Rn Rd
 * ORR (vector):  0 0 0 01110 10 1 Rm 00011 1 Rn Rd
 * MOV (vector):  same as ORR Vd, Vn, Vn
 */

/* Helper: emit a raw 32-bit instruction */
static void simd_emit(jit_memory_t *jit, uint32_t inst) {
    emit_raw(jit, inst);
}

/* FADD Sd, Sn, Sm (scalar single-precision) */
void emit_sse_addss(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    /* FADD Sd, Sd, Sm: 0001 1110 001 Sm 0010 10 Sn Sd */
    uint32_t inst = 0x1E202800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* FADD Dd, Dn, Dm (scalar double-precision) */
void emit_sse_addsd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E602800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* FSUB Sd, Sn, Sm */
void emit_sse_subss(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E203800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_subsd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E603800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* FMUL Sd, Sn, Sm */
void emit_sse_mulss(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E200800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_mulsd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E600800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* FDIV Sd, Sn, Sm */
void emit_sse_divss(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E201800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_divsd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E601800 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* FSQRT Sd, Sn */
void emit_sse_sqrtss(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    /* FSQRT Sd, Sn: 0001 1110 001 00000 1100 00 Sn Sd */
    uint32_t inst = 0x1E21C000 | (src << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_sqrtsd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E61C000 | (src << 5) | dst;
    simd_emit(jit, inst);
}

/* FCMP Sn, Sm (sets NZCV flags) */
void emit_sse_ucomiss(jit_memory_t *jit, uint32_t src1, uint32_t src2) {
    /* FCMP Sn, Sm: 0001 1110 001 Sm 00 1000 Sn 00000 */
    uint32_t inst = 0x1E202000 | (src2 << 16) | (src1 << 5);
    simd_emit(jit, inst);
}

void emit_sse_ucomisd(jit_memory_t *jit, uint32_t src1, uint32_t src2) {
    uint32_t inst = 0x1E602000 | (src2 << 16) | (src1 << 5);
    simd_emit(jit, inst);
}

/* FMOV Sd, Sn */
void emit_sse_movss_reg(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E204000 | (src << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_movsd_reg(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x1E604000 | (src << 5) | dst;
    simd_emit(jit, inst);
}

/* MOV Vd.16B, Vn.16B (128-bit register move = ORR Vd, Vn, Vn) */
void emit_sse_movaps_reg(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    /* ORR Vd.16B, Vn.16B, Vn.16B: 0100 1110 101 Vm 00011 1 Vn Vd */
    uint32_t inst = 0x4EA01C00 | (src << 16) | (src << 5) | dst;
    simd_emit(jit, inst);
}

/* EOR Vd.16B, Vd.16B, Vs.16B (128-bit XOR) */
void emit_sse_xorps(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x6E201C00 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

void emit_sse_xorpd(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    /* Same encoding as xorps - operates on full 128-bit register */
    emit_sse_xorps(jit, dst, src);
}

/* AND Vd.16B, Vd.16B, Vs.16B */
void emit_sse_andps(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x0E201C00 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* ORR Vd.16B, Vd.16B, Vs.16B */
void emit_sse_orps(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    uint32_t inst = 0x0EA01C00 | (src << 16) | (dst << 5) | dst;
    simd_emit(jit, inst);
}

/* PXOR = EOR (same as XORPS for integer SIMD) */
void emit_sse_pxor(jit_memory_t *jit, uint32_t dst, uint32_t src) {
    emit_sse_xorps(jit, dst, src);
}
