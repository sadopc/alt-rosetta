/*
 * flags.c - Lazy flags engine for x86_64 to ARM64 translation
 *
 * x86 sets flags on nearly every arithmetic/logic instruction, but most flags
 * are never consumed. The lazy flags approach stores operation metadata in
 * dedicated ARM64 registers and only materializes actual flag values when a
 * conditional instruction (Jcc, SETcc, CMOVcc, PUSHF) needs them.
 *
 * Dedicated ARM64 registers:
 *   X19 = flags operation type (flags_op_t)
 *   X25 = operand 1
 *   X26 = operand 2
 *   X27 = result
 *   X28 = operand size (1/2/4/8)
 */

#include "flags.h"
#include "debug.h"

/*
 * emit_set_lazy_flags - Store lazy flags metadata into dedicated registers.
 *
 * Called after each x86 arithmetic/logic instruction is translated. The
 * operands and result are already in ARM64 registers; we just record which
 * operation produced them so we can reconstruct flags later.
 */
void emit_set_lazy_flags(jit_memory_t *jit, flags_op_t op, uint32_t op1_reg,
                         uint32_t op2_reg, uint32_t result_reg, operand_size_t size)
{
    /* Store operation type */
    emit_mov_imm64(jit, ARM_FLAGS_OP, (uint64_t)op);

    /* Store operand 1 */
    emit_mov_reg(jit, true, ARM_FLAGS_OP1, op1_reg);

    /* Store operand 2 */
    emit_mov_reg(jit, true, ARM_FLAGS_OP2, op2_reg);

    /* Store result */
    emit_mov_reg(jit, true, ARM_FLAGS_RES, result_reg);

    /* Store operand size */
    emit_mov_imm64(jit, ARM_FLAGS_SIZE, (uint64_t)size);
}

/*
 * emit_compute_flags - Reconstruct ARM64 NZCV from lazy flags state.
 *
 * This is the core of the lazy flags engine. When a conditional instruction
 * needs to check a condition, we re-execute the stored operation on the stored
 * operands to set the ARM64 NZCV flags, then the caller can use B.cond etc.
 *
 * Strategy by operation type:
 *   SUB/CMP: SUBS scratch, op1, op2 -> sets NZCV identically to x86
 *   ADD:     ADDS scratch, op1, op2 -> sets NZCV
 *   AND/TEST/OR/XOR: ANDS scratch, result, result (for Z and N);
 *                     but CF/OF are always 0 for logical ops, so for most
 *                     conditions this is sufficient.
 *   INC/DEC: like ADD/SUB with op2=1, but CF is preserved (not affected)
 *
 * For now we dispatch on the operation type stored in X19. We load X19 and
 * compare against known values, branching to the appropriate reconstruction.
 */
void emit_compute_flags(jit_memory_t *jit, x86_cc_t cc)
{
    (void)cc;

    /*
     * General approach: load the flags_op type and dispatch.
     *
     * For SUB/CMP (most common), emit: SUBS X22, X25, X26
     * For ADD, emit: ADDS X22, X25, X26
     * For AND/TEST/OR/XOR, emit: ANDS X22, X27, X27 (test result against itself)
     * For INC, emit: ADDS X22, X25, #1
     * For DEC, emit: SUBS X22, X25, #1
     *
     * We use a cascade of CMP + B.EQ to dispatch.
     */

    uint32_t *patch_sub = NULL;
    uint32_t *patch_add = NULL;
    uint32_t *patch_logic = NULL;
    uint32_t *patch_inc = NULL;
    uint32_t *patch_dec = NULL;
    uint32_t *done_sub = NULL;
    uint32_t *done_add = NULL;
    uint32_t *done_logic = NULL;
    uint32_t *done_inc = NULL;

    /* Compare flags_op (X19) against FLAGS_OP_SUB */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_SUB);
    patch_sub = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0); /* will patch to SUB handler */

    /* Compare against FLAGS_OP_ADD */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_ADD);
    patch_add = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0); /* will patch to ADD handler */

    /* Compare against logical ops: AND, OR, XOR (treat them all the same) */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_AND);
    patch_logic = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_OR);
    uint32_t *patch_or = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_XOR);
    uint32_t *patch_xor = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Compare against INC */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_INC);
    patch_inc = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Compare against DEC */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_DEC);
    patch_dec = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Fallback for NEG, SHL, SHR, SAR, IMUL: treat as SUB for flag reconstruction */
    /* SUBS X22, X25, X26 */
    emit_subs_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    uint32_t *done_fallback = emit_get_cursor(jit);
    emit_b(jit, 0); /* branch to done */

    /* --- SUB/CMP handler --- */
    /* Must use correct operand width (X28=size): 32-bit SUBS for SIZE_32, 64-bit for SIZE_64.
     * Using the wrong width gives incorrect N/V flags (e.g., -5 looks positive in 64-bit). */
    uint32_t *sub_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_sub, sub_handler);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);  /* Check if size==8 (64-bit) */
    uint32_t *sub_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    /* 32-bit (or smaller) SUB path */
    emit_subs_reg(jit, false, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    done_sub = emit_get_cursor(jit);
    emit_b(jit, 0);
    /* 64-bit SUB path */
    uint32_t *sub_64_handler = emit_get_cursor(jit);
    emit_patch_bcond(sub_64, sub_64_handler);
    emit_subs_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    uint32_t *done_sub64 = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* --- ADD handler --- */
    uint32_t *add_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_add, add_handler);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);
    uint32_t *add_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_adds_reg(jit, false, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    done_add = emit_get_cursor(jit);
    emit_b(jit, 0);
    uint32_t *add_64_handler = emit_get_cursor(jit);
    emit_patch_bcond(add_64, add_64_handler);
    emit_adds_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    uint32_t *done_add64 = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* --- Logical (AND/OR/XOR/TEST) handler --- */
    uint32_t *logic_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_logic, logic_handler);
    emit_patch_bcond(patch_or, logic_handler);
    emit_patch_bcond(patch_xor, logic_handler);
    /* For logical ops: CF=0, OF=0, ZF/SF from result. Use ANDS. */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);
    uint32_t *logic_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_ands_reg(jit, false, ARM_TMP0, ARM_FLAGS_RES, ARM_FLAGS_RES);
    done_logic = emit_get_cursor(jit);
    emit_b(jit, 0);
    uint32_t *logic_64_handler = emit_get_cursor(jit);
    emit_patch_bcond(logic_64, logic_64_handler);
    emit_ands_reg(jit, true, ARM_TMP0, ARM_FLAGS_RES, ARM_FLAGS_RES);
    uint32_t *done_logic64 = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* --- INC handler (like ADD with imm 1, but CF not affected) --- */
    uint32_t *inc_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_inc, inc_handler);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);
    uint32_t *inc_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_adds_imm(jit, false, ARM_TMP0, ARM_FLAGS_OP1, 1);
    done_inc = emit_get_cursor(jit);
    emit_b(jit, 0);
    uint32_t *inc_64_handler = emit_get_cursor(jit);
    emit_patch_bcond(inc_64, inc_64_handler);
    emit_adds_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP1, 1);
    uint32_t *done_inc64 = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* --- DEC handler (like SUB with imm 1, but CF not affected) --- */
    uint32_t *dec_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_dec, dec_handler);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);
    uint32_t *dec_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_subs_imm(jit, false, ARM_TMP0, ARM_FLAGS_OP1, 1);
    uint32_t *done_dec = emit_get_cursor(jit);
    emit_b(jit, 0);
    uint32_t *dec_64_handler = emit_get_cursor(jit);
    emit_patch_bcond(dec_64, dec_64_handler);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP1, 1);
    /* Fall through to done */

    /* --- Done --- */
    uint32_t *done = emit_get_cursor(jit);
    emit_patch_b(done_sub, done);
    emit_patch_b(done_sub64, done);
    emit_patch_b(done_add, done);
    emit_patch_b(done_add64, done);
    emit_patch_b(done_logic, done);
    emit_patch_b(done_logic64, done);
    emit_patch_b(done_inc, done);
    emit_patch_b(done_inc64, done);
    emit_patch_b(done_dec, done);
    emit_patch_b(done_fallback, done);

    /* NZCV is now set from the reconstructed operation */
}

/*
 * emit_fused_cmp_jcc - Fused CMP + conditional branch.
 *
 * When we detect CMP immediately followed by Jcc, we skip the lazy flags
 * mechanism entirely and emit a single SUBS + B.cond sequence. This is
 * much more efficient since CMP+Jcc is the most common pattern.
 */
uint32_t *emit_fused_cmp_jcc(jit_memory_t *jit, uint32_t op1_reg, uint32_t op2_reg,
                              bool is_64bit, x86_cc_t cc, int32_t branch_offset)
{
    /* Emit SUBS XZR, op1, op2 (sets NZCV without storing result) */
    emit_subs_reg(jit, is_64bit, 31 /* XZR/WZR */, op1_reg, op2_reg);

    /* Map x86 condition code to ARM64 */
    arm64_cc_t arm_cc = x86_cc_to_arm64(cc);

    /* Emit B.cond with the given offset (caller will patch if needed) */
    uint32_t *branch_addr = emit_get_cursor(jit);
    emit_bcond(jit, arm_cc, branch_offset);

    return branch_addr;
}

/*
 * emit_get_cf - Compute x86 carry flag from lazy state.
 *
 * CF semantics differ by operation:
 *   ADD: CF=1 if unsigned overflow (carry out)
 *   SUB: CF=1 if borrow (unsigned op1 < op2)
 *   Logical: CF=0
 *   INC/DEC: CF unchanged (we don't handle this perfectly yet)
 *
 * Note: x86 CF for SUB is inverted relative to ARM64 C flag.
 *   x86 SUB sets CF=1 when there's a borrow (op1 < op2)
 *   ARM64 SUBS sets C=1 when there's NO borrow (op1 >= op2)
 */
void emit_get_cf(jit_memory_t *jit, uint32_t dst_reg)
{
    /*
     * Dispatch on operation type. For simplicity, handle the two main cases:
     * - ADD: ADDS scratch, op1, op2 -> CSET dst, CS
     * - SUB/CMP: SUBS scratch, op1, op2 -> CSET dst, CC (inverted!)
     * - Logical: MOV dst, #0
     */

    /* Check if this is an ADD operation */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_ADD);
    uint32_t *patch_add = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Check for logical ops (AND/OR/XOR/TEST) -> CF=0 */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_AND);
    uint32_t *patch_and = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_OR);
    uint32_t *patch_or = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_XOR);
    uint32_t *patch_xor = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Default: SUB/CMP path */
    emit_subs_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    emit_cset(jit, true, dst_reg, ARM_CC_CC); /* x86 CF = ARM64 !C for SUB */
    uint32_t *done_sub = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* ADD path */
    uint32_t *add_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_add, add_handler);
    emit_adds_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    emit_cset(jit, true, dst_reg, ARM_CC_CS); /* x86 CF = ARM64 C for ADD */
    uint32_t *done_add = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* Logical ops path: CF = 0 */
    uint32_t *logic_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_and, logic_handler);
    emit_patch_bcond(patch_or, logic_handler);
    emit_patch_bcond(patch_xor, logic_handler);
    emit_movz(jit, true, dst_reg, 0, 0);
    /* Fall through to done */

    uint32_t *done = emit_get_cursor(jit);
    emit_patch_b(done_sub, done);
    emit_patch_b(done_add, done);
}

/*
 * emit_get_zf - Compute x86 zero flag from lazy state.
 *
 * ZF=1 when result is zero (at the appropriate operand size).
 * This is the same for all operation types.
 */
void emit_get_zf(jit_memory_t *jit, uint32_t dst_reg)
{
    /*
     * Mask the result to the operand size, then check if zero.
     * For simplicity, use 64-bit check on result (handles SIZE_64).
     * For sub-64-bit sizes, we should mask first, but the stored result
     * should already be appropriately sized.
     */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_RES, 0);
    emit_cset(jit, true, dst_reg, ARM_CC_EQ);
}

/*
 * emit_get_sf - Compute x86 sign flag from lazy state.
 *
 * SF = most significant bit of the result at the given operand size.
 * Must test the correct bit based on operand size (X28):
 *   SIZE_64(8): bit 63, SIZE_32(4): bit 31, SIZE_16(2): bit 15, SIZE_8(1): bit 7
 */
void emit_get_sf(jit_memory_t *jit, uint32_t dst_reg)
{
    /* Check size==8 for 64-bit, otherwise use 32-bit test (covers SIZE_32).
     * SIZE_8 and SIZE_16 would need further refinement but are rare. */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_SIZE, 8);
    uint32_t *patch_64 = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    /* 32-bit (or smaller): test W register for sign bit at bit 31 */
    emit_subs_imm(jit, false, ARM_TMP0, ARM_FLAGS_RES, 0);
    emit_cset(jit, true, dst_reg, ARM_CC_MI);
    uint32_t *done_32 = emit_get_cursor(jit);
    emit_b(jit, 0);
    /* 64-bit path */
    uint32_t *handler_64 = emit_get_cursor(jit);
    emit_patch_bcond(patch_64, handler_64);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_RES, 0);
    emit_cset(jit, true, dst_reg, ARM_CC_MI);
    /* fall through to done */
    uint32_t *done = emit_get_cursor(jit);
    emit_patch_b(done_32, done);
}

/*
 * emit_get_of - Compute x86 overflow flag from lazy state.
 *
 * OF semantics differ by operation:
 *   ADD: signed overflow (both operands same sign, result different sign)
 *   SUB: signed overflow
 *   Logical: OF=0
 */
void emit_get_of(jit_memory_t *jit, uint32_t dst_reg)
{
    /* Check for logical ops first -> OF=0 */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_AND);
    uint32_t *patch_logic = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_OR);
    uint32_t *patch_or = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_XOR);
    uint32_t *patch_xor = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Check for ADD */
    emit_subs_imm(jit, true, ARM_TMP0, ARM_FLAGS_OP, (uint32_t)FLAGS_OP_ADD);
    uint32_t *patch_add = emit_get_cursor(jit);
    emit_bcond(jit, ARM_CC_EQ, 0);

    /* Default: SUB path */
    emit_subs_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    emit_cset(jit, true, dst_reg, ARM_CC_VS);
    uint32_t *done_sub = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* ADD path */
    uint32_t *add_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_add, add_handler);
    emit_adds_reg(jit, true, ARM_TMP0, ARM_FLAGS_OP1, ARM_FLAGS_OP2);
    emit_cset(jit, true, dst_reg, ARM_CC_VS);
    uint32_t *done_add = emit_get_cursor(jit);
    emit_b(jit, 0);

    /* Logical ops: OF=0 */
    uint32_t *logic_handler = emit_get_cursor(jit);
    emit_patch_bcond(patch_logic, logic_handler);
    emit_patch_bcond(patch_or, logic_handler);
    emit_patch_bcond(patch_xor, logic_handler);
    emit_movz(jit, true, dst_reg, 0, 0);
    /* Fall through */

    uint32_t *done = emit_get_cursor(jit);
    emit_patch_b(done_sub, done);
    emit_patch_b(done_add, done);
}

/*
 * emit_get_pf - Compute x86 parity flag from lazy state.
 *
 * PF = 1 if the low byte of the result has an even number of set bits.
 * This is independent of the operation type.
 *
 * We compute PF using a software bit-counting sequence:
 *   1. Extract low byte of result
 *   2. XOR fold: byte ^= (byte >> 4); byte ^= (byte >> 2); byte ^= (byte >> 1)
 *   3. PF = !(byte & 1)  (even parity -> PF=1)
 */
void emit_get_pf(jit_memory_t *jit, uint32_t dst_reg)
{
    /*
     * Parity flag computation via XOR folding:
     *   val = result & 0xFF
     *   val ^= val >> 4
     *   val ^= val >> 2
     *   val ^= val >> 1
     *   PF = (val ^ 1) & 1   (even parity -> PF=1)
     *
     * We use dst_reg as the working register and ARM_TMP0 as scratch.
     */

    /* Extract low byte of result */
    emit_uxtb(jit, dst_reg, ARM_FLAGS_RES);

    /* dst ^= (dst >> 4) */
    emit_mov_reg(jit, false, ARM_TMP0, dst_reg);
    emit_ubfm(jit, false, ARM_TMP0, ARM_TMP0, 4, 31); /* LSR W, #4 */
    emit_eor_reg(jit, false, dst_reg, dst_reg, ARM_TMP0);

    /* dst ^= (dst >> 2) */
    emit_mov_reg(jit, false, ARM_TMP0, dst_reg);
    emit_ubfm(jit, false, ARM_TMP0, ARM_TMP0, 2, 31); /* LSR W, #2 */
    emit_eor_reg(jit, false, dst_reg, dst_reg, ARM_TMP0);

    /* dst ^= (dst >> 1) */
    emit_mov_reg(jit, false, ARM_TMP0, dst_reg);
    emit_ubfm(jit, false, ARM_TMP0, ARM_TMP0, 1, 31); /* LSR W, #1 */
    emit_eor_reg(jit, false, dst_reg, dst_reg, ARM_TMP0);

    /* Now bit 0 of dst is 1 if odd parity, 0 if even parity.
     * PF=1 means even parity, so we need to invert bit 0. */
    emit_mov_imm32(jit, ARM_TMP0, 1);
    emit_eor_reg(jit, false, dst_reg, dst_reg, ARM_TMP0); /* flip bit 0 */
    emit_and_reg(jit, false, dst_reg, dst_reg, ARM_TMP0); /* mask to bit 0 */
}

/*
 * flags_compute_eflags - Software EFLAGS computation (non-JIT).
 *
 * Used by PUSHF or debugging to materialize the full EFLAGS register value
 * from the lazy flags state in the CPU state structure.
 */
uint64_t flags_compute_eflags(const x86_cpu_state_t *state)
{
    uint64_t eflags = 0x0002; /* Bit 1 is always set in EFLAGS */
    uint64_t op1 = state->flags_op1;
    uint64_t op2 = state->flags_op2;
    uint64_t res = state->flags_res;
    uint8_t size = state->flags_size;

    if (state->flags_op == FLAGS_OP_NONE)
        return eflags;

    /* Compute size mask */
    uint64_t size_mask;
    int sign_bit;
    switch (size) {
    case 1:  size_mask = 0xFF;               sign_bit = 7;  break;
    case 2:  size_mask = 0xFFFF;             sign_bit = 15; break;
    case 4:  size_mask = 0xFFFFFFFF;         sign_bit = 31; break;
    case 8:  size_mask = 0xFFFFFFFFFFFFFFFF; sign_bit = 63; break;
    default: size_mask = 0xFFFFFFFFFFFFFFFF; sign_bit = 63; break;
    }

    /* Mask operands and result to size */
    op1 &= size_mask;
    op2 &= size_mask;
    res &= size_mask;

    /* ZF: result is zero */
    if (res == 0)
        eflags |= X86_ZF;

    /* SF: sign bit of result */
    if ((res >> sign_bit) & 1)
        eflags |= X86_SF;

    /* PF: parity of low byte (even number of set bits -> PF=1) */
    {
        uint8_t low = (uint8_t)(res & 0xFF);
        low ^= low >> 4;
        low ^= low >> 2;
        low ^= low >> 1;
        if (!(low & 1))
            eflags |= X86_PF;
    }

    /* CF and OF depend on the operation */
    switch (state->flags_op) {
    case FLAGS_OP_ADD:
        /* CF: unsigned overflow */
        if (res < op1)
            eflags |= X86_CF;
        /* OF: signed overflow (both operands same sign, result different) */
        if (((op1 ^ res) & (op2 ^ res)) >> sign_bit & 1)
            eflags |= X86_OF;
        break;

    case FLAGS_OP_SUB:
        /* CF: borrow (unsigned op1 < op2) */
        if (op1 < op2)
            eflags |= X86_CF;
        /* OF: signed overflow */
        if (((op1 ^ op2) & (op1 ^ res)) >> sign_bit & 1)
            eflags |= X86_OF;
        break;

    case FLAGS_OP_AND:
    case FLAGS_OP_OR:
    case FLAGS_OP_XOR:
        /* Logical operations: CF=0, OF=0 */
        break;

    case FLAGS_OP_INC:
        /* CF is not affected by INC. OF: overflow if op1 was max positive. */
        if (op1 == (size_mask >> 1))
            eflags |= X86_OF;
        break;

    case FLAGS_OP_DEC:
        /* CF is not affected by DEC. OF: overflow if op1 was min negative (sign bit set, rest zero). */
        if (op1 == ((uint64_t)1 << sign_bit))
            eflags |= X86_OF;
        break;

    case FLAGS_OP_NEG:
        /* CF=1 unless operand was 0 */
        if (op1 != 0)
            eflags |= X86_CF;
        /* OF=1 if op1 was the minimum signed value */
        if (op1 == ((uint64_t)1 << sign_bit))
            eflags |= X86_OF;
        break;

    case FLAGS_OP_SHL:
        /* CF = last bit shifted out (bit [size*8 - shift_amount] of original) */
        if (op2 > 0 && op2 <= (uint64_t)(sign_bit + 1)) {
            if ((op1 >> (sign_bit + 1 - op2)) & 1)
                eflags |= X86_CF;
        }
        /* OF: defined only for shift_count=1 */
        if (op2 == 1) {
            uint64_t msb_res = (res >> sign_bit) & 1;
            uint64_t cf = (op1 >> sign_bit) & 1;
            if (msb_res ^ cf)
                eflags |= X86_OF;
        }
        break;

    case FLAGS_OP_SHR:
        /* CF = last bit shifted out */
        if (op2 > 0 && op2 <= (uint64_t)(sign_bit + 1)) {
            if ((op1 >> (op2 - 1)) & 1)
                eflags |= X86_CF;
        }
        /* OF: for count=1, OF = MSB of original */
        if (op2 == 1) {
            if ((op1 >> sign_bit) & 1)
                eflags |= X86_OF;
        }
        break;

    case FLAGS_OP_SAR:
        /* CF = last bit shifted out (same as SHR) */
        if (op2 > 0 && op2 <= (uint64_t)(sign_bit + 1)) {
            if ((op1 >> (op2 - 1)) & 1)
                eflags |= X86_CF;
        }
        /* OF = 0 for SAR with count=1 (sign doesn't change) */
        break;

    case FLAGS_OP_IMUL:
        /* CF=OF=1 if result doesn't fit in the destination size */
        {
            /* For single-operand IMUL: if sign-extending the low half != full result */
            int64_t sres = (int64_t)res;
            bool overflow = false;
            switch (size) {
            case 1: overflow = (sres != (int8_t)sres);  break;
            case 2: overflow = (sres != (int16_t)sres); break;
            case 4: overflow = (sres != (int32_t)sres); break;
            case 8: /* For 64-bit IMUL, we'd need the 128-bit result */ break;
            }
            if (overflow) {
                eflags |= X86_CF;
                eflags |= X86_OF;
            }
        }
        break;

    default:
        break;
    }

    /* AF (auxiliary carry) - bit 4 carry for BCD. Approximate. */
    if (state->flags_op == FLAGS_OP_ADD || state->flags_op == FLAGS_OP_SUB) {
        if (((op1 ^ op2 ^ res) >> 4) & 1)
            eflags |= X86_AF;
    }

    /* Direction flag */
    if (state->direction_flag)
        eflags |= X86_DF;

    return eflags;
}
