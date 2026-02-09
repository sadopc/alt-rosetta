/*
 * simd.h - SSE → NEON translation helpers
 *
 * Maps x86 SSE/SSE2 scalar and packed operations to ARM64 NEON equivalents.
 * XMM0-XMM15 map to ARM64 V0-V15.
 */

#ifndef SIMD_H
#define SIMD_H

#include "alt_rosetta.h"
#include "arm64_emit.h"

/* Emit ARM64 NEON code for SSE scalar float operations.
 * dst/src are NEON register numbers (0-15, mapping from XMM0-XMM15). */
void emit_sse_addss(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_addsd(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_subss(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_subsd(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_mulss(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_mulsd(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_divss(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_divsd(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_sqrtss(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_sqrtsd(jit_memory_t *jit, uint32_t dst, uint32_t src);

/* SSE comparison (sets x86 EFLAGS from float comparison) */
void emit_sse_ucomiss(jit_memory_t *jit, uint32_t src1, uint32_t src2);
void emit_sse_ucomisd(jit_memory_t *jit, uint32_t src1, uint32_t src2);

/* SSE data movement */
void emit_sse_movss_reg(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_movsd_reg(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_movaps_reg(jit_memory_t *jit, uint32_t dst, uint32_t src);

/* SSE bitwise */
void emit_sse_xorps(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_xorpd(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_andps(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_orps(jit_memory_t *jit, uint32_t dst, uint32_t src);
void emit_sse_pxor(jit_memory_t *jit, uint32_t dst, uint32_t src);

#endif /* SIMD_H */
