/*
 * arm64_emit.c - ARM64 instruction encoder
 *
 * Encodes fixed-size (32-bit) ARM64 instructions into a JIT code buffer.
 */

#include "arm64_emit.h"

/* --- Data Processing (Register) --- */

/* ADD Rd, Rn, Rm (no shift) */
void emit_add_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 01011 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x0B << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ADDS Rd, Rn, Rm */
void emit_adds_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 1 01011 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x2B << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SUB Rd, Rn, Rm */
void emit_sub_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 1 0 01011 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x4B << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SUBS Rd, Rn, Rm */
void emit_subs_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 1 1 01011 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x6B << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* AND Rd, Rn, Rm */
void emit_and_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 00 01010 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x0A << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ANDS Rd, Rn, Rm */
void emit_ands_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 11 01010 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x6A << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ORR Rd, Rn, Rm */
void emit_orr_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 01 01010 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x2A << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* EOR Rd, Rn, Rm */
void emit_eor_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 10 01010 00 0 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x4A << 24) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ORN Rd, Rn, Rm */
void emit_orn_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 01 01010 00 1 Rm 000000 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x2A << 24) | (1 << 21) | (rm << 16) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* Shifted register: ADD */
void emit_add_reg_shifted(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn,
                          uint32_t rm, arm64_shift_t shift, uint32_t amount) {
    /* sf 0 0 01011 shift 0 Rm imm6 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x0B << 24) | ((uint32_t)shift << 22) |
                    (rm << 16) | ((amount & 0x3F) << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* Shifted register: SUB */
void emit_sub_reg_shifted(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn,
                          uint32_t rm, arm64_shift_t shift, uint32_t amount) {
    /* sf 1 0 01011 shift 0 Rm imm6 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x4B << 24) | ((uint32_t)shift << 22) |
                    (rm << 16) | ((amount & 0x3F) << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* LSLV Rd, Rn, Rm */
void emit_lslv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11010110 Rm 0010 00 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (rm << 16) |
                    (0x08 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* LSRV Rd, Rn, Rm */
void emit_lsrv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11010110 Rm 0010 01 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (rm << 16) |
                    (0x09 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ASRV Rd, Rn, Rm */
void emit_asrv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11010110 Rm 0010 10 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (rm << 16) |
                    (0x0A << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* MUL Rd, Rn, Rm  (MADD Rd, Rn, Rm, XZR) */
void emit_mul(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11011 000 Rm 0 11111 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD8 << 21) | (rm << 16) |
                    (31 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SMULH Rd, Rn, Rm (always 64-bit) */
void emit_smulh(jit_memory_t *jit, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* 1 0 0 11011 010 Rm 0 11111 Rn Rd */
    uint32_t inst = (1u << 31) | (0xD6 << 21) | (0x2 << 21) |
                    (rm << 16) | (31 << 10) | (rn << 5) | rd;
    /* Re-encode properly: 10011011010 Rm 0 Ra Rn Rd with Ra=31 */
    inst = 0x9B400000 | (rm << 16) | (31 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* UMULH Rd, Rn, Rm (always 64-bit) */
void emit_umulh(jit_memory_t *jit, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* 1 0 0 11011 110 Rm 0 11111 Rn Rd */
    uint32_t inst = 0x9BC00000 | (rm << 16) | (31 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* UDIV Rd, Rn, Rm */
void emit_udiv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11010110 Rm 00001 0 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (rm << 16) |
                    (0x02 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SDIV Rd, Rn, Rm */
void emit_sdiv(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm) {
    /* sf 0 0 11010110 Rm 00001 1 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (rm << 16) |
                    (0x03 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* MSUB Rd, Rn, Rm, Ra  (Rd = Ra - Rn*Rm) */
void emit_msub(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, uint32_t ra) {
    /* sf 0 0 11011 000 Rm 1 Ra Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD8 << 21) | (rm << 16) |
                    (1u << 15) | (ra << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* --- Data Processing (Immediate) --- */

/* ADD Rd, Rn, #imm12 */
void emit_add_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12) {
    /* sf 0 0 10001 00 imm12 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x11 << 24) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* ADDS Rd, Rn, #imm12 */
void emit_adds_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12) {
    /* sf 0 1 10001 00 imm12 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x31 << 24) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SUB Rd, Rn, #imm12 */
void emit_sub_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12) {
    /* sf 1 0 10001 00 imm12 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x51 << 24) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SUBS Rd, Rn, #imm12 */
void emit_subs_imm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t imm12) {
    /* sf 1 1 10001 00 imm12 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0x71 << 24) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* --- Moves --- */

/* MOV Rd, Rm  (ORR Rd, XZR, Rm) */
void emit_mov_reg(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rm) {
    emit_orr_reg(jit, sf, rd, 31, rm);
}

/* MOVZ Rd, #imm16, LSL #shift */
void emit_movz(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift) {
    /* sf 10 100101 hw imm16 Rd  (hw = shift/16) */
    uint32_t hw = shift / 16;
    uint32_t inst = ((uint32_t)sf << 31) | (0xA5 << 23) | (hw << 21) |
                    ((uint32_t)imm16 << 5) | rd;
    jit_emit(jit, inst);
}

/* MOVK Rd, #imm16, LSL #shift */
void emit_movk(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift) {
    /* sf 11 100101 hw imm16 Rd */
    uint32_t hw = shift / 16;
    uint32_t inst = ((uint32_t)sf << 31) | (0xE5 << 23) | (hw << 21) |
                    ((uint32_t)imm16 << 5) | rd;
    jit_emit(jit, inst);
}

/* MOVN Rd, #imm16, LSL #shift */
void emit_movn(jit_memory_t *jit, bool sf, uint32_t rd, uint16_t imm16, uint8_t shift) {
    /* sf 00 100101 hw imm16 Rd */
    uint32_t hw = shift / 16;
    uint32_t inst = ((uint32_t)sf << 31) | (0x25 << 23) | (hw << 21) |
                    ((uint32_t)imm16 << 5) | rd;
    jit_emit(jit, inst);
}

/* Load arbitrary 64-bit immediate into Xd */
void emit_mov_imm64(jit_memory_t *jit, uint32_t rd, uint64_t value) {
    if (value == 0) {
        emit_movz(jit, 1, rd, 0, 0);
        return;
    }

    /* Check if all-ones or near all-ones (MOVN optimization) */
    uint64_t inv = ~value;
    uint16_t chunks[4] = {
        (uint16_t)(value >>  0),
        (uint16_t)(value >> 16),
        (uint16_t)(value >> 32),
        (uint16_t)(value >> 48),
    };
    uint16_t inv_chunks[4] = {
        (uint16_t)(inv >>  0),
        (uint16_t)(inv >> 16),
        (uint16_t)(inv >> 32),
        (uint16_t)(inv >> 48),
    };

    /* Count non-zero chunks */
    int nz_count = 0, inv_nz_count = 0;
    for (int i = 0; i < 4; i++) {
        if (chunks[i] != 0) nz_count++;
        if (inv_chunks[i] != 0) inv_nz_count++;
    }

    /* Use MOVN if it saves instructions */
    if (inv_nz_count < nz_count) {
        bool first = true;
        for (int i = 0; i < 4; i++) {
            if (inv_chunks[i] != 0 || first) {
                if (first) {
                    emit_movn(jit, 1, rd, inv_chunks[i], (uint8_t)(i * 16));
                    first = false;
                } else {
                    emit_movk(jit, 1, rd, chunks[i], (uint8_t)(i * 16));
                }
            }
        }
        /* Patch up: we need MOVK for all non-first chunks that differ from NOT */
        return;
    }

    /* Standard MOVZ + MOVK sequence */
    bool first = true;
    for (int i = 0; i < 4; i++) {
        if (chunks[i] != 0 || (first && i == 3)) {
            if (first) {
                emit_movz(jit, 1, rd, chunks[i], (uint8_t)(i * 16));
                first = false;
            } else {
                emit_movk(jit, 1, rd, chunks[i], (uint8_t)(i * 16));
            }
        }
    }
    /* If nothing was emitted (shouldn't happen since value != 0), emit MOVZ #0 */
    if (first) {
        emit_movz(jit, 1, rd, 0, 0);
    }
}

/* Load arbitrary 32-bit immediate into Wd */
void emit_mov_imm32(jit_memory_t *jit, uint32_t rd, uint32_t value) {
    if (value == 0) {
        emit_movz(jit, 0, rd, 0, 0);
        return;
    }

    uint16_t lo = (uint16_t)(value & 0xFFFF);
    uint16_t hi = (uint16_t)(value >> 16);
    uint32_t inv = ~value;
    uint16_t inv_lo = (uint16_t)(inv & 0xFFFF);
    uint16_t inv_hi = (uint16_t)(inv >> 16);

    /* Check if MOVN is better */
    int nz = (lo != 0) + (hi != 0);
    int inv_nz = (inv_lo != 0) + (inv_hi != 0);

    if (inv_nz < nz) {
        /* Use MOVN */
        if (inv_lo == 0 && inv_hi == 0) {
            emit_movn(jit, 0, rd, 0, 0);
        } else if (inv_hi == 0) {
            emit_movn(jit, 0, rd, inv_lo, 0);
        } else {
            emit_movn(jit, 0, rd, inv_hi, 16);
            if (lo != (uint16_t)0xFFFF) {
                emit_movk(jit, 0, rd, lo, 0);
            }
        }
        return;
    }

    if (hi == 0) {
        emit_movz(jit, 0, rd, lo, 0);
    } else if (lo == 0) {
        emit_movz(jit, 0, rd, hi, 16);
    } else {
        emit_movz(jit, 0, rd, lo, 0);
        emit_movk(jit, 0, rd, hi, 16);
    }
}

/* --- Loads and Stores --- */

/* LDR Xt/Wt, [Xn, #offset] (unsigned offset) */
void emit_ldr_imm(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int32_t offset) {
    /* Size: sf=1 -> 8 bytes (scale=3), sf=0 -> 4 bytes (scale=2) */
    uint32_t size = sf ? 3 : 2;
    uint32_t scale = sf ? 8 : 4;
    uint32_t imm12 = (uint32_t)offset / scale;
    /* 1x 111 00 1 01 imm12 Rn Rt */
    uint32_t inst = (size << 30) | (0x39 << 24) | (1 << 22) | (imm12 << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STR Xt/Wt, [Xn, #offset] (unsigned offset) */
void emit_str_imm(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int32_t offset) {
    uint32_t size = sf ? 3 : 2;
    uint32_t scale = sf ? 8 : 4;
    uint32_t imm12 = (uint32_t)offset / scale;
    /* 1x 111 00 1 00 imm12 Rn Rt */
    uint32_t inst = (size << 30) | (0x39 << 24) | (0 << 22) | (imm12 << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDRB Wt, [Xn, #imm12] */
void emit_ldrb_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 00 111 00 1 01 imm12 Rn Rt */
    uint32_t inst = (0x39 << 24) | (1 << 22) | ((offset & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STRB Wt, [Xn, #imm12] */
void emit_strb_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 00 111 00 1 00 imm12 Rn Rt */
    uint32_t inst = (0x39 << 24) | (0 << 22) | ((offset & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDRH Wt, [Xn, #imm12*2] */
void emit_ldrh_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 01 111 00 1 01 imm12 Rn Rt  (imm12 = offset/2) */
    uint32_t imm12 = offset / 2;
    uint32_t inst = (1u << 30) | (0x39 << 24) | (1 << 22) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STRH Wt, [Xn, #imm12*2] */
void emit_strh_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 01 111 00 1 00 imm12 Rn Rt  (imm12 = offset/2) */
    uint32_t imm12 = offset / 2;
    uint32_t inst = (1u << 30) | (0x39 << 24) | (0 << 22) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDR Xt, [Xn, Xm] (register offset, no extend/shift) */
void emit_ldr_reg(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t rm) {
    /* 1x 111 00 0 11 Rm 011 0 10 Rn Rt (option=011=LSL, S=0) */
    uint32_t size = sf ? 3 : 2;
    uint32_t inst = (size << 30) | (0x38 << 24) | (1 << 22) | (1 << 21) |
                    (rm << 16) | (0x03 << 13) | (0 << 12) | (0x02 << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STR Xt, [Xn, Xm] (register offset) */
void emit_str_reg(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t rm) {
    uint32_t size = sf ? 3 : 2;
    uint32_t inst = (size << 30) | (0x38 << 24) | (0 << 22) | (1 << 21) |
                    (rm << 16) | (0x03 << 13) | (0 << 12) | (0x02 << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDR Xt, [Xn], #simm9 (post-index) */
void emit_ldr_post(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9) {
    /* 1x 111 00 0 x 0 imm9 01 Rn Rt  (x=1 for load) */
    uint32_t size = sf ? 3 : 2;
    uint32_t imm9 = (uint32_t)simm9 & 0x1FF;
    uint32_t inst = (size << 30) | (0x38 << 24) | (1 << 22) | (0 << 21) |
                    (imm9 << 12) | (0x01 << 10) | (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STR Xt, [Xn, #simm9]! (pre-index) */
void emit_str_pre(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9) {
    /* 1x 111 00 0 x 0 imm9 11 Rn Rt  (x=0 for store) */
    uint32_t size = sf ? 3 : 2;
    uint32_t imm9 = (uint32_t)simm9 & 0x1FF;
    uint32_t inst = (size << 30) | (0x38 << 24) | (0 << 22) | (0 << 21) |
                    (imm9 << 12) | (0x03 << 10) | (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDR Xt, [Xn, #simm9]! (pre-index) */
void emit_ldr_pre(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, int16_t simm9) {
    uint32_t size = sf ? 3 : 2;
    uint32_t imm9 = (uint32_t)simm9 & 0x1FF;
    uint32_t inst = (size << 30) | (0x38 << 24) | (1 << 22) | (0 << 21) |
                    (imm9 << 12) | (0x03 << 10) | (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* STP Xt1, Xt2, [Xn, #imm7*scale] */
void emit_stp(jit_memory_t *jit, bool sf, uint32_t rt1, uint32_t rt2, uint32_t rn, int16_t offset) {
    /* x0 101 0 010 imm7 Rt2 Rn Rt1 */
    uint32_t opc = sf ? 2 : 0;
    uint32_t scale = sf ? 8 : 4;
    uint32_t imm7 = ((uint32_t)(offset / (int16_t)scale)) & 0x7F;
    uint32_t inst = (opc << 30) | (0xA << 26) | (0x2 << 23) | (imm7 << 15) |
                    (rt2 << 10) | (rn << 5) | rt1;
    jit_emit(jit, inst);
}

/* LDP Xt1, Xt2, [Xn, #imm7*scale] */
void emit_ldp(jit_memory_t *jit, bool sf, uint32_t rt1, uint32_t rt2, uint32_t rn, int16_t offset) {
    uint32_t opc = sf ? 2 : 0;
    uint32_t scale = sf ? 8 : 4;
    uint32_t imm7 = ((uint32_t)(offset / (int16_t)scale)) & 0x7F;
    /* LDP signed offset: opc 101 0 010 1 imm7 Rt2 Rn Rt1 (L=1 at bit 22) */
    uint32_t inst = (opc << 30) | (0xA << 26) | (0x2 << 23) | (1 << 22) | (imm7 << 15) |
                    (rt2 << 10) | (rn << 5) | rt1;
    jit_emit(jit, inst);
}

/* LDRSW Xt, [Xn, #imm12*4] */
void emit_ldrsw_imm(jit_memory_t *jit, uint32_t rt, uint32_t rn, int32_t offset) {
    /* 10 111 00 1 10 imm12 Rn Rt */
    uint32_t imm12 = (uint32_t)offset / 4;
    uint32_t inst = (0x2 << 30) | (0x39 << 24) | (0x2 << 22) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDRSH Xt, [Xn, #imm12*2] */
void emit_ldrsh(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 01 111 00 1 1x imm12 Rn Rt  (x=0 for 64-bit dest, x=1 for 32-bit dest) */
    uint32_t imm12 = offset / 2;
    uint32_t opc = sf ? 0x2 : 0x3;  /* sf=1 -> sign-extend to 64 (opc=10), sf=0 -> to 32 (opc=11) */
    uint32_t inst = (0x1 << 30) | (0x39 << 24) | (opc << 22) | ((imm12 & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* LDRSB Xt, [Xn, #imm12] */
void emit_ldrsb(jit_memory_t *jit, bool sf, uint32_t rt, uint32_t rn, uint32_t offset) {
    /* 00 111 00 1 1x imm12 Rn Rt */
    uint32_t opc = sf ? 0x2 : 0x3;
    uint32_t inst = (0x0 << 30) | (0x39 << 24) | (opc << 22) | ((offset & 0xFFF) << 10) |
                    (rn << 5) | rt;
    jit_emit(jit, inst);
}

/* --- Branches --- */

/* B #offset (offset in bytes, will be converted to words) */
void emit_b(jit_memory_t *jit, int32_t offset) {
    /* 000101 imm26 */
    int32_t imm26 = offset >> 2;
    uint32_t inst = (0x05 << 26) | ((uint32_t)imm26 & 0x03FFFFFF);
    jit_emit(jit, inst);
}

/* BL #offset */
void emit_bl(jit_memory_t *jit, int32_t offset) {
    /* 100101 imm26 */
    int32_t imm26 = offset >> 2;
    uint32_t inst = (0x25 << 26) | ((uint32_t)imm26 & 0x03FFFFFF);
    jit_emit(jit, inst);
}

/* BR Xn */
void emit_br(jit_memory_t *jit, uint32_t rn) {
    /* 1101011 0000 11111 000000 Rn 00000 */
    uint32_t inst = 0xD61F0000 | (rn << 5);
    jit_emit(jit, inst);
}

/* BLR Xn */
void emit_blr(jit_memory_t *jit, uint32_t rn) {
    /* 1101011 0001 11111 000000 Rn 00000 */
    uint32_t inst = 0xD63F0000 | (rn << 5);
    jit_emit(jit, inst);
}

/* RET {Xn} */
void emit_ret(jit_memory_t *jit, uint32_t rn) {
    /* 1101011 0010 11111 000000 Rn 00000 */
    uint32_t inst = 0xD65F0000 | (rn << 5);
    jit_emit(jit, inst);
}

/* B.cond #offset (offset in bytes) */
void emit_bcond(jit_memory_t *jit, arm64_cc_t cc, int32_t offset) {
    /* 0101010 0 imm19 0 cond */
    int32_t imm19 = offset >> 2;
    uint32_t inst = (0x54 << 24) | (((uint32_t)imm19 & 0x7FFFF) << 5) | (uint32_t)cc;
    jit_emit(jit, inst);
}

/* CBZ Xt, #offset */
void emit_cbz(jit_memory_t *jit, bool sf, uint32_t rt, int32_t offset) {
    /* sf 011010 0 imm19 Rt */
    int32_t imm19 = offset >> 2;
    uint32_t inst = ((uint32_t)sf << 31) | (0x34 << 24) |
                    (((uint32_t)imm19 & 0x7FFFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* CBNZ Xt, #offset */
void emit_cbnz(jit_memory_t *jit, bool sf, uint32_t rt, int32_t offset) {
    /* sf 011010 1 imm19 Rt */
    int32_t imm19 = offset >> 2;
    uint32_t inst = ((uint32_t)sf << 31) | (0x35 << 24) |
                    (((uint32_t)imm19 & 0x7FFFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* TBZ Xt, #bit, #offset */
void emit_tbz(jit_memory_t *jit, uint32_t rt, uint32_t bit, int32_t offset) {
    /* b5 011011 0 b40 imm14 Rt */
    uint32_t b5 = (bit >> 5) & 1;
    uint32_t b40 = bit & 0x1F;
    int32_t imm14 = offset >> 2;
    uint32_t inst = (b5 << 31) | (0x36 << 24) | (b40 << 19) |
                    (((uint32_t)imm14 & 0x3FFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* TBNZ Xt, #bit, #offset */
void emit_tbnz(jit_memory_t *jit, uint32_t rt, uint32_t bit, int32_t offset) {
    /* b5 011011 1 b40 imm14 Rt */
    uint32_t b5 = (bit >> 5) & 1;
    uint32_t b40 = bit & 0x1F;
    int32_t imm14 = offset >> 2;
    uint32_t inst = (b5 << 31) | (0x37 << 24) | (b40 << 19) |
                    (((uint32_t)imm14 & 0x3FFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* --- Extensions --- */

/* SXTB: SBFM Rd, Rn, #0, #7 */
void emit_sxtb(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn) {
    emit_sbfm(jit, sf, rd, rn, 0, 7);
}

/* SXTH: SBFM Rd, Rn, #0, #15 */
void emit_sxth(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn) {
    emit_sbfm(jit, sf, rd, rn, 0, 15);
}

/* SXTW: SBFM Xd, Xn, #0, #31 (always 64-bit) */
void emit_sxtw(jit_memory_t *jit, uint32_t rd, uint32_t rn) {
    emit_sbfm(jit, 1, rd, rn, 0, 31);
}

/* UXTB: UBFM Wd, Wn, #0, #7 (32-bit) */
void emit_uxtb(jit_memory_t *jit, uint32_t rd, uint32_t rn) {
    emit_ubfm(jit, 0, rd, rn, 0, 7);
}

/* UXTH: UBFM Wd, Wn, #0, #15 (32-bit) */
void emit_uxth(jit_memory_t *jit, uint32_t rd, uint32_t rn) {
    emit_ubfm(jit, 0, rd, rn, 0, 15);
}

/* --- Conditional Select --- */

/* CSEL Rd, Rn, Rm, cond */
void emit_csel(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, arm64_cc_t cc) {
    /* sf 0 0 11010100 Rm cond 00 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD4 << 21) | (rm << 16) |
                    ((uint32_t)cc << 12) | (0x0 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* CSINC Rd, Rn, Rm, cond */
void emit_csinc(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t rm, arm64_cc_t cc) {
    /* sf 0 0 11010100 Rm cond 01 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD4 << 21) | (rm << 16) |
                    ((uint32_t)cc << 12) | (0x1 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* CSET Rd, cond  (CSINC Rd, XZR, XZR, invert(cond)) */
void emit_cset(jit_memory_t *jit, bool sf, uint32_t rd, arm64_cc_t cc) {
    arm64_cc_t inv = (arm64_cc_t)((uint32_t)cc ^ 1);
    emit_csinc(jit, sf, rd, 31, 31, inv);
}

/* --- System --- */

/* SVC #imm16 */
void emit_svc(jit_memory_t *jit, uint16_t imm16) {
    /* 11010100 000 imm16 000 01 */
    uint32_t inst = 0xD4000001 | ((uint32_t)imm16 << 5);
    jit_emit(jit, inst);
}

/* NOP */
void emit_nop(jit_memory_t *jit) {
    jit_emit(jit, 0xD503201F);
}

/* BRK #imm16 */
void emit_brk(jit_memory_t *jit, uint16_t imm16) {
    /* 11010100 001 imm16 000 00 */
    uint32_t inst = 0xD4200000 | ((uint32_t)imm16 << 5);
    jit_emit(jit, inst);
}

/* MRS Xt, sysreg */
void emit_mrs(jit_memory_t *jit, uint32_t rt, uint32_t sysreg) {
    /* 1101 0101 0011 op0:2 op1:3 CRn:4 CRm:4 op2:3 Rt:5 */
    uint32_t inst = 0xD5300000 | ((sysreg & 0xFFFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* MSR sysreg, Xt */
void emit_msr(jit_memory_t *jit, uint32_t sysreg, uint32_t rt) {
    /* 1101 0101 0001 ... */
    uint32_t inst = 0xD5100000 | ((sysreg & 0xFFFF) << 5) | rt;
    jit_emit(jit, inst);
}

/* --- Bitfield --- */

/* UBFM Rd, Rn, immr, imms */
void emit_ubfm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms) {
    /* sf 10 100110 N immr imms Rn Rd  (N=sf for 64-bit) */
    uint32_t N = sf ? 1 : 0;
    uint32_t inst = ((uint32_t)sf << 31) | (0x53 << 24) | (N << 22) |
                    ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* SBFM Rd, Rn, immr, imms */
void emit_sbfm(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn, uint32_t immr, uint32_t imms) {
    /* sf 00 100110 N immr imms Rn Rd */
    uint32_t N = sf ? 1 : 0;
    uint32_t inst = ((uint32_t)sf << 31) | (0x13 << 24) | (N << 22) |
                    ((immr & 0x3F) << 16) | ((imms & 0x3F) << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* --- Reverse / Count --- */

/* CLZ Rd, Rn */
void emit_clz(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn) {
    /* sf 1 0 11010110 00000 00010 0 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (0x04 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* RBIT Rd, Rn */
void emit_rbit(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn) {
    /* sf 1 0 11010110 00000 00000 0 Rn Rd */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (0x00 << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* REV Rd, Rn */
void emit_rev(jit_memory_t *jit, bool sf, uint32_t rd, uint32_t rn) {
    /* sf 1 0 11010110 00000 0000 sf|1 0 Rn Rd */
    /* sf=0: REV32 (opc=10 -> bits[11:10] = 10), sf=1: REV64 (opc=11 -> bits[11:10] = 11) */
    uint32_t opc = sf ? 0x03 : 0x02;  /* bit pattern for the opcode2 field */
    uint32_t inst = ((uint32_t)sf << 31) | (0xD6 << 21) | (opc << 10) | (rn << 5) | rd;
    /* Actually the full encoding:
     * sf 1 0 11010110 00000 0000xx Rn Rd where xx depends on REV type
     * REV (sf=1, 64-bit): sf=1, opc=11 -> 0x0300
     * REV (sf=0, 32-bit): sf=0, opc=10 -> 0x0200
     * But we also need the upper bits of opcode2 correct.
     * Full: sf 1011010110 00000 00001 sf 0 Rn Rd
     */
    inst = ((uint32_t)sf << 31) | (0x5AC << 16) | (0x00 << 12) |
           ((sf ? 3u : 2u) << 10) | (rn << 5) | rd;
    jit_emit(jit, inst);
}

/* --- Memory Barriers --- */

/* DMB option */
void emit_dmb(jit_memory_t *jit, uint8_t option) {
    /* 1101 0101 0000 0011 0011 CRm 1 01 11111 */
    uint32_t inst = 0xD50330BF | ((uint32_t)(option & 0xF) << 8);
    jit_emit(jit, inst);
}

/* DSB option */
void emit_dsb(jit_memory_t *jit, uint8_t option) {
    /* 1101 0101 0000 0011 0011 CRm 1 00 11111 */
    uint32_t inst = 0xD503309F | ((uint32_t)(option & 0xF) << 8);
    jit_emit(jit, inst);
}

/* ISB */
void emit_isb(jit_memory_t *jit) {
    /* 1101 0101 0000 0011 0011 0110 1 00 11111 = 0xD5033FDF */
    /* ISB SY: CRm=0110=6, option bits */
    jit_emit(jit, 0xD5033FDF);
}

/* --- Raw instruction emission --- */

void emit_raw(jit_memory_t *jit, uint32_t inst) {
    jit_emit(jit, inst);
}

uint32_t *emit_get_cursor(jit_memory_t *jit) {
    return jit_cursor(jit);
}

/* Patch a B instruction at addr to jump to target */
void emit_patch_b(uint32_t *addr, uint32_t *target) {
    int64_t diff = (int64_t)((uint8_t *)target - (uint8_t *)addr);
    int32_t imm26 = (int32_t)(diff >> 2);
    /* Preserve the opcode (top 6 bits), replace imm26 */
    *addr = (*addr & 0xFC000000) | ((uint32_t)imm26 & 0x03FFFFFF);
}

/* Patch a B.cond instruction at addr to jump to target */
void emit_patch_bcond(uint32_t *addr, uint32_t *target) {
    int64_t diff = (int64_t)((uint8_t *)target - (uint8_t *)addr);
    int32_t imm19 = (int32_t)(diff >> 2);
    /* B.cond: bits[23:5] = imm19, bits[3:0] = cond, bit[4] = 0 */
    *addr = (*addr & 0xFF00001F) | (((uint32_t)imm19 & 0x7FFFF) << 5);
}

/* Map x86 condition code to ARM64 condition code */
arm64_cc_t x86_cc_to_arm64(x86_cc_t cc) {
    switch (cc) {
    case X86_CC_O:   return ARM_CC_VS;  /* Overflow */
    case X86_CC_NO:  return ARM_CC_VC;  /* No overflow */
    case X86_CC_B:   return ARM_CC_CC;  /* Below (CF=1) -> CC (C=0 after SUB means borrow) */
    case X86_CC_AE:  return ARM_CC_CS;  /* Above/Equal (CF=0) -> CS */
    case X86_CC_E:   return ARM_CC_EQ;  /* Equal */
    case X86_CC_NE:  return ARM_CC_NE;  /* Not equal */
    case X86_CC_BE:  return ARM_CC_LS;  /* Below/Equal */
    case X86_CC_A:   return ARM_CC_HI;  /* Above */
    case X86_CC_S:   return ARM_CC_MI;  /* Sign (negative) */
    case X86_CC_NS:  return ARM_CC_PL;  /* Not sign */
    case X86_CC_P:   return ARM_CC_VS;  /* Parity - no direct mapping, VS as placeholder */
    case X86_CC_NP:  return ARM_CC_VC;  /* Not parity */
    case X86_CC_L:   return ARM_CC_LT;  /* Less (signed) */
    case X86_CC_GE:  return ARM_CC_GE;  /* Greater/Equal (signed) */
    case X86_CC_LE:  return ARM_CC_LE;  /* Less/Equal (signed) */
    case X86_CC_G:   return ARM_CC_GT;  /* Greater (signed) */
    default:         return ARM_CC_AL;
    }
}
