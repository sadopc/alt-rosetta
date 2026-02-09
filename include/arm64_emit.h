/*
 * arm64_emit.h - ARM64 instruction encoder
 *
 * Provides functions to emit fixed-size (32-bit) ARM64 instructions
 * into a JIT code buffer. Each function encodes one ARM64 instruction
 * and writes it via the JIT memory manager.
 */

#ifndef ARM64_EMIT_H
#define ARM64_EMIT_H

#include "alt_rosetta.h"
#include "x86_decode.h"
#include "memory.h"

/* ARM64 condition codes (matching the 4-bit encoding in branch instructions) */
typedef enum {
    ARM_CC_EQ = 0x0,   /* Equal (Z=1) */
    ARM_CC_NE = 0x1,   /* Not equal (Z=0) */
    ARM_CC_CS = 0x2,   /* Carry set / unsigned >= (C=1) */
    ARM_CC_CC = 0x3,   /* Carry clear / unsigned < (C=0) */
    ARM_CC_MI = 0x4,   /* Minus / negative (N=1) */
    ARM_CC_PL = 0x5,   /* Plus / positive or zero (N=0) */
    ARM_CC_VS = 0x6,   /* Overflow (V=1) */
    ARM_CC_VC = 0x7,   /* No overflow (V=0) */
    ARM_CC_HI = 0x8,   /* Unsigned > (C=1 and Z=0) */
    ARM_CC_LS = 0x9,   /* Unsigned <= (C=0 or Z=1) */
    ARM_CC_GE = 0xA,   /* Signed >= (N=V) */
    ARM_CC_LT = 0xB,   /* Signed < (N≠V) */
    ARM_CC_GT = 0xC,   /* Signed > (Z=0 and N=V) */
    ARM_CC_LE = 0xD,   /* Signed <= (Z=1 or N≠V) */
    ARM_CC_AL = 0xE,   /* Always */
    ARM_CC_NV = 0xF,   /* Never (also used as AL in some encodings) */
} arm64_cc_t;

/* Shift types for data processing instructions */
typedef enum {
    ARM_SHIFT_LSL = 0,
    ARM_SHIFT_LSR = 1,
    ARM_SHIFT_ASR = 2,
    ARM_SHIFT_ROR = 3,
} arm64_shift_t;

/* ---- Emit functions ---- */
/* All emit functions take a jit_memory_t* and write one 32-bit instruction. */

/* --- Data Processing (Register) --- */

/* ADD Rd, Rn, Rm [shifted] (64-bit if sf=1) */
void emit_add_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* ADDS Rd, Rn, Rm (sets NZCV flags) */
void emit_adds_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* SUB Rd, Rn, Rm */
void emit_sub_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* SUBS Rd, Rn, Rm (sets NZCV flags) */
void emit_subs_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* AND Rd, Rn, Rm */
void emit_and_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* ANDS Rd, Rn, Rm (sets NZ flags) */
void emit_ands_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* ORR Rd, Rn, Rm */
void emit_orr_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* EOR Rd, Rn, Rm */
void emit_eor_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* ORN Rd, Rn, Rm (bitwise OR NOT) */
void emit_orn_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* Shifted register variants */
void emit_add_reg_shifted(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn,
                          uint32_t rm, arm64_shift_t shift, uint32_t amount);
void emit_sub_reg_shifted(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn,
                          uint32_t rm, arm64_shift_t shift, uint32_t amount);

/* LSL/LSR/ASR Rd, Rn, Rm (variable shift) */
void emit_lslv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);
void emit_lsrv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);
void emit_asrv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* MUL Rd, Rn, Rm (MADD Rd, Rn, Rm, XZR) */
void emit_mul(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* SMULH Rd, Rn, Rm (signed multiply high 64x64→128, upper 64 bits) */
void emit_smulh(jit_memory_t *jit, uint32_t rd, uint32_t rn, uint32_t rm);

/* UMULH Rd, Rn, Rm (unsigned multiply high) */
void emit_umulh(jit_memory_t *jit, uint32_t rd, uint32_t rn, uint32_t rm);

/* UDIV Rd, Rn, Rm */
void emit_udiv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* SDIV Rd, Rn, Rm */
void emit_sdiv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm);

/* MSUB Rd, Rn, Rm, Ra (Rd = Ra - Rn*Rm) - used for remainder computation */
void emit_msub(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, uint32_t ra);

/* --- Data Processing (Immediate) --- */

/* ADD Rd, Rn, #imm12 */
void emit_add_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12);

/* ADDS Rd, Rn, #imm12 (sets flags) */
void emit_adds_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12);

/* SUB Rd, Rn, #imm12 */
void emit_sub_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12);

/* SUBS Rd, Rn, #imm12 (sets flags) */
void emit_subs_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12);

/* --- Moves --- */

/* MOV Rd, Rm (ORR Rd, XZR, Rm) */
void emit_mov_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rm);

/* MOVZ Rd, #imm16, LSL #shift (zero-then-insert) */
void emit_movz(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift);

/* MOVK Rd, #imm16, LSL #shift (keep-then-insert) */
void emit_movk(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift);

/* MOVN Rd, #imm16, LSL #shift (NOT-then-insert) */
void emit_movn(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift);

/* Helper: Load an arbitrary 64-bit immediate into Rd.
 * Uses MOVZ/MOVK sequence (1-4 instructions depending on value). */
void emit_mov_imm64(jit_memory_t *jit, uint32_t rd, uint64_t value);

/* Helper: Load an arbitrary 32-bit immediate into Wd (upper 32 cleared). */
void emit_mov_imm32(jit_memory_t *jit, uint32_t rd, uint32_t value);

/* --- Loads and Stores --- */

/* LDR Xt, [Xn, #imm12*8] (64-bit load, unsigned offset) */
void emit_ldr_imm(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int32_t offset);

/* STR Xt, [Xn, #imm12*8] (64-bit store, unsigned offset) */
void emit_str_imm(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int32_t offset);

/* LDRB Wt, [Xn, #imm12] (byte load) */
void emit_ldrb_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset);

/* STRB Wt, [Xn, #imm12] (byte store) */
void emit_strb_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset);

/* LDRH Wt, [Xn, #imm12*2] (halfword load) */
void emit_ldrh_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset);

/* STRH Wt, [Xn, #imm12*2] (halfword store) */
void emit_strh_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset);

/* LDR Xt, [Xn, Xm] (register offset) */
void emit_ldr_reg(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t rm);

/* STR Xt, [Xn, Xm] (register offset) */
void emit_str_reg(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t rm);

/* LDR Xt, [Xn], #simm9 (post-index) */
void emit_ldr_post(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9);

/* STR Xt, [Xn, #simm9]! (pre-index) */
void emit_str_pre(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9);

/* LDR Xt, [Xn, #simm9]! (pre-index) */
void emit_ldr_pre(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9);

/* STP Xt1, Xt2, [Xn, #imm7*8] (store pair) */
void emit_stp(jit_memory_t *jit, bool sf, uint32_t rt1, uint32_t rt2, uint32_t rn, int16_t offset);

/* LDP Xt1, Xt2, [Xn, #imm7*8] (load pair) */
void emit_ldp(jit_memory_t *jit, bool sf, uint32_t rt1, uint32_t rt2, uint32_t rn, int16_t offset);

/* LDRSW Xt, [Xn, #imm12*4] (sign-extend 32→64 load) */
void emit_ldrsw_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, int32_t offset);

/* LDRSH Xt, [Xn, #imm12*2] (sign-extend 16→64 load) */
void emit_ldrsh(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t offset);

/* LDRSB Xt, [Xn, #imm12] (sign-extend 8→64 load) */
void emit_ldrsb(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t offset);

/* --- Branches --- */

/* B #offset (unconditional branch, ±128 MB) */
void emit_b(jit_memory_t *jit, int32_t offset);

/* BL #offset (branch with link) */
void emit_bl(jit_memory_t *jit, int32_t offset);

/* BR Xn (branch to register) */
void emit_br(jit_memory_t *jit, uint32_t rn);

/* BLR Xn (branch with link to register) */
void emit_blr(jit_memory_t *jit, uint32_t rn);

/* RET {Xn} (return, defaults to X30) */
void emit_ret(jit_memory_t *jit, uint32_t rn);

/* B.cond #offset (conditional branch, ±1 MB) */
void emit_bcond(jit_memory_t *jit, arm64_cc_t cc, int32_t offset);

/* CBZ Xt, #offset (compare and branch if zero) */
void emit_cbz(jit_memory_t *jit, bool sf, uint32_t rt, int32_t offset);

/* CBNZ Xt, #offset (compare and branch if not zero) */
void emit_cbnz(jit_memory_t *jit, bool sf, uint32_t rt, int32_t offset);

/* TBZ Xt, #bit, #offset (test bit and branch if zero) */
void emit_tbz(jit_memory_t *jit, uint32_t rt, uint32_t bit, int32_t offset);

/* TBNZ Xt, #bit, #offset (test bit and branch if not zero) */
void emit_tbnz(jit_memory_t *jit, uint32_t rt, uint32_t bit, int32_t offset);

/* --- Extensions --- */

/* SXTB Rd, Rn (sign-extend byte) */
void emit_sxtb(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn);

/* SXTH Rd, Rn (sign-extend halfword) */
void emit_sxth(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn);

/* SXTW Rd, Rn (sign-extend word) */
void emit_sxtw(jit_memory_t *jit, uint32_t rd, uint32_t rn);

/* UXTB Rd, Rn (zero-extend byte → AND Rd, Rn, #0xFF) */
void emit_uxtb(jit_memory_t *jit, uint32_t rd, uint32_t rn);

/* UXTH Rd, Rn (zero-extend halfword → AND Rd, Rn, #0xFFFF) */
void emit_uxth(jit_memory_t *jit, uint32_t rd, uint32_t rn);

/* --- Conditional Select --- */

/* CSEL Rd, Rn, Rm, cond */
void emit_csel(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, arm64_cc_t cc);

/* CSINC Rd, Rn, Rm, cond */
void emit_csinc(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, arm64_cc_t cc);

/* CSET Rd, cond (CSINC Rd, XZR, XZR, invert(cond)) */
void emit_cset(jit_memory_t *jit, bool sf, uint32_t rd, arm64_cc_t cc);

/* --- System --- */

/* SVC #imm16 (supervisor call) */
void emit_svc(jit_memory_t *jit, uint16_t imm16);

/* NOP */
void emit_nop(jit_memory_t *jit);

/* BRK #imm16 (breakpoint) */
void emit_brk(jit_memory_t *jit, uint16_t imm16);

/* MRS Xt, sysreg */
void emit_mrs(jit_memory_t *jit, uint32_t rt, uint32_t sysreg);

/* MSR sysreg, Xt */
void emit_msr(jit_memory_t *jit, uint32_t sysreg, uint32_t rt);

/* NZCV system register encoding for MRS/MSR */
#define SYSREG_NZCV 0xDA10  /* S3_3_C4_C2_0 */

/* --- Bitfield --- */

/* UBFM Rd, Rn, immr, imms (unsigned bitfield move) */
void emit_ubfm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms);

/* SBFM Rd, Rn, immr, imms (signed bitfield move) */
void emit_sbfm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms);

/* --- Reverse / Count --- */

/* CLZ Rd, Rn (count leading zeros) */
void emit_clz(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn);

/* RBIT Rd, Rn (reverse bits) */
void emit_rbit(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn);

/* REV Rd, Rn (reverse bytes) */
void emit_rev(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn);

/* --- Memory Barriers --- */

/* DMB (data memory barrier) */
void emit_dmb(jit_memory_t *jit, uint8_t option);
#define DMB_ISH    0xB  /* Inner shareable, full barrier */
#define DMB_ISHLD  0x9  /* Inner shareable, load barrier */
#define DMB_ISHST  0xA  /* Inner shareable, store barrier */

/* DSB (data synchronization barrier) */
void emit_dsb(jit_memory_t *jit, uint8_t option);

/* ISB (instruction synchronization barrier) */
void emit_isb(jit_memory_t *jit);

/* --- Raw instruction emission --- */

/* Emit a raw 32-bit instruction word */
void emit_raw(jit_memory_t *jit, uint32_t inst);

/* Get the current code position (for patching branches later) */
uint32_t *emit_get_cursor(jit_memory_t *jit);

/* Patch a branch instruction at addr to jump to target */
void emit_patch_b(uint32_t *addr, uint32_t *target);
void emit_patch_bcond(uint32_t *addr, uint32_t *target);

/* Map x86 condition code to ARM64 condition code.
 * Note: x86 CF is inverted relative to ARM64 C flag for subtraction. */
arm64_cc_t x86_cc_to_arm64(x86_cc_t cc);

#endif /* ARM64_EMIT_H */
