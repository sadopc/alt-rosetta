/*
 * flags.h - Lazy flags engine
 *
 * x86 EFLAGS are expensive to compute after every instruction. Instead we use
 * "lazy flags": store the operation, operands, and result, and only compute
 * specific flags when they are actually consumed (by Jcc, CMOVcc, SETcc, etc.).
 *
 * The lazy state is kept in dedicated ARM64 registers:
 *   X19 = operation type (flags_op_t)
 *   X25 = operand 1
 *   X26 = operand 2
 *   X27 = result
 *   X28 = operand size (1/2/4/8)
 */

#ifndef FLAGS_H
#define FLAGS_H

#include "alt_rosetta.h"
#include "cpu_state.h"
#include "arm64_emit.h"

/* Emit code to store lazy flags state.
 * After an arithmetic/logic instruction, we save the operation metadata
 * so flags can be computed later on demand. */
void emit_set_lazy_flags(jit_memory_t *jit, flags_op_t op, uint32_t op1_reg,
                         uint32_t op2_reg, uint32_t result_reg, operand_size_t size);

/* Emit code to compute a specific x86 flag from lazy state and set ARM64 NZCV.
 * This is called before conditional branches/moves.
 *
 * For common patterns (CMP+Jcc), we can fuse into a single SUBS + B.cond
 * without going through the lazy mechanism. */
void emit_compute_flags(jit_memory_t *jit, x86_cc_t cc);

/* Emit a fused CMP+Jcc pattern.
 * When we see CMP followed immediately by Jcc, we emit SUBS + B.cond directly
 * without storing lazy flags. Returns the branch instruction address for patching.
 * op1_reg and op2_reg are the ARM64 registers holding the x86 CMP operands. */
uint32_t *emit_fused_cmp_jcc(jit_memory_t *jit, uint32_t op1_reg, uint32_t op2_reg,
                              bool is_64bit, x86_cc_t cc, int32_t branch_offset);

/* Emit code to compute x86 carry flag (CF) from lazy state.
 * Writes CF into a scratch register (0 or 1). */
void emit_get_cf(jit_memory_t *jit, uint32_t dst_reg);

/* Emit code to compute x86 zero flag (ZF) from lazy state. */
void emit_get_zf(jit_memory_t *jit, uint32_t dst_reg);

/* Emit code to compute x86 sign flag (SF) from lazy state. */
void emit_get_sf(jit_memory_t *jit, uint32_t dst_reg);

/* Emit code to compute x86 overflow flag (OF) from lazy state. */
void emit_get_of(jit_memory_t *jit, uint32_t dst_reg);

/* Emit code to compute x86 parity flag (PF) from lazy state.
 * PF = parity of low byte of result (1 if even number of set bits). */
void emit_get_pf(jit_memory_t *jit, uint32_t dst_reg);

/* Software-compute all flags from lazy state (used when we need to
 * materialize the full EFLAGS value, e.g., for PUSHF). */
uint64_t flags_compute_eflags(const x86_cpu_state_t *state);

/* x86 EFLAGS bit positions */
#define X86_CF  (1 << 0)    /* Carry */
#define X86_PF  (1 << 2)    /* Parity */
#define X86_AF  (1 << 4)    /* Auxiliary carry */
#define X86_ZF  (1 << 6)    /* Zero */
#define X86_SF  (1 << 7)    /* Sign */
#define X86_OF  (1 << 11)   /* Overflow */
#define X86_DF  (1 << 10)   /* Direction */

#endif /* FLAGS_H */
