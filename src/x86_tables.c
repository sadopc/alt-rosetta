/*
 * x86_tables.c - Opcode lookup tables for x86_64 decoding
 *
 * Provides one-byte, two-byte, and group opcode tables for the x86_64
 * instruction set decoder.
 */

#include "x86_tables.h"

/* Helper macros for table construction */
#define INVALID_ENTRY \
    { X86_OP_INVALID, X86_CAT_INVALID, ENC_NONE, SIZE_32, 0, false, 0, NULL }

#define PREFIX_ENTRY(name) \
    { X86_OP_INVALID, X86_CAT_INVALID, ENC_PREFIX, SIZE_32, 0, false, 0, name }

/* ALU rm,r / r,rm / acc,imm pattern (6 opcodes per ALU op) */
#define ALU_ENTRIES(base, op, cat, mnem) \
    [(base)+0] = { op, cat, ENC_MODRM_REG, SIZE_8,  2, true,  0, mnem }, \
    [(base)+1] = { op, cat, ENC_MODRM_REG, SIZE_32, 2, true,  0, mnem }, \
    [(base)+2] = { op, cat, ENC_MODRM_REG, SIZE_8,  2, true,  0, mnem }, \
    [(base)+3] = { op, cat, ENC_MODRM_REG, SIZE_32, 2, true,  0, mnem }, \
    [(base)+4] = { op, cat, ENC_ACC_IMM,   SIZE_8,  2, false, 1, mnem }, \
    [(base)+5] = { op, cat, ENC_ACC_IMM,   SIZE_32, 2, false, 4, mnem }

/*
 * One-byte opcode table (256 entries)
 */
const opcode_entry_t opcode_table_1byte[256] = {
    /* 0x00-0x05: ADD */
    ALU_ENTRIES(0x00, X86_OP_ADD, X86_CAT_ARITHMETIC, "add"),
    /* 0x06-0x07: invalid in 64-bit mode */

    /* 0x08-0x0D: OR */
    ALU_ENTRIES(0x08, X86_OP_OR, X86_CAT_LOGIC, "or"),

    /* 0x0F: escape to 2-byte table */
    [0x0F] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_ESCAPE, SIZE_32, 0, false, 0, NULL },

    /* 0x10-0x15: ADC */
    ALU_ENTRIES(0x10, X86_OP_ADC, X86_CAT_ARITHMETIC, "adc"),

    /* 0x18-0x1D: SBB */
    ALU_ENTRIES(0x18, X86_OP_SBB, X86_CAT_ARITHMETIC, "sbb"),

    /* 0x20-0x25: AND */
    ALU_ENTRIES(0x20, X86_OP_AND, X86_CAT_LOGIC, "and"),

    /* 0x26: ES segment override prefix */
    [0x26] = PREFIX_ENTRY("es"),
    /* 0x2E: CS segment override prefix */
    [0x2E] = PREFIX_ENTRY("cs"),

    /* 0x28-0x2D: SUB */
    ALU_ENTRIES(0x28, X86_OP_SUB, X86_CAT_ARITHMETIC, "sub"),

    /* 0x30-0x35: XOR */
    ALU_ENTRIES(0x30, X86_OP_XOR, X86_CAT_LOGIC, "xor"),

    /* 0x36: SS segment override prefix */
    [0x36] = PREFIX_ENTRY("ss"),
    /* 0x3E: DS segment override prefix */
    [0x3E] = PREFIX_ENTRY("ds"),

    /* 0x38-0x3D: CMP */
    ALU_ENTRIES(0x38, X86_OP_CMP, X86_CAT_COMPARE, "cmp"),

    /* 0x40-0x4F: REX prefixes */
    [0x40] = PREFIX_ENTRY("rex"),
    [0x41] = PREFIX_ENTRY("rex.b"),
    [0x42] = PREFIX_ENTRY("rex.x"),
    [0x43] = PREFIX_ENTRY("rex.xb"),
    [0x44] = PREFIX_ENTRY("rex.r"),
    [0x45] = PREFIX_ENTRY("rex.rb"),
    [0x46] = PREFIX_ENTRY("rex.rx"),
    [0x47] = PREFIX_ENTRY("rex.rxb"),
    [0x48] = PREFIX_ENTRY("rex.w"),
    [0x49] = PREFIX_ENTRY("rex.wb"),
    [0x4A] = PREFIX_ENTRY("rex.wx"),
    [0x4B] = PREFIX_ENTRY("rex.wxb"),
    [0x4C] = PREFIX_ENTRY("rex.wr"),
    [0x4D] = PREFIX_ENTRY("rex.wrb"),
    [0x4E] = PREFIX_ENTRY("rex.wrx"),
    [0x4F] = PREFIX_ENTRY("rex.wrxb"),

    /* 0x50-0x57: PUSH reg */
    [0x50] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x51] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x52] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x53] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x54] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x55] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x56] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },
    [0x57] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "push" },

    /* 0x58-0x5F: POP reg */
    [0x58] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x59] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5A] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5B] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5C] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5D] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5E] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },
    [0x5F] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_64, 1, false, 0, "pop" },

    /* 0x63: MOVSXD */
    [0x63] = { X86_OP_MOVSXD, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_32, 2, true, 0, "movsxd" },

    /* 0x64-0x65: FS/GS segment override prefixes */
    [0x64] = PREFIX_ENTRY("fs"),
    [0x65] = PREFIX_ENTRY("gs"),

    /* 0x66: operand size override */
    [0x66] = PREFIX_ENTRY("data16"),
    /* 0x67: address size override */
    [0x67] = PREFIX_ENTRY("addr32"),

    /* 0x68: PUSH imm32 */
    [0x68] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_FIXED, SIZE_64, 1, false, 4, "push" },
    /* 0x69: IMUL r, r/m, imm32 */
    [0x69] = { X86_OP_IMUL, X86_CAT_ARITHMETIC, ENC_MODRM_REG, SIZE_32, 3, true, 4, "imul" },
    /* 0x6A: PUSH imm8 */
    [0x6A] = { X86_OP_PUSH, X86_CAT_DATA_XFER, ENC_FIXED, SIZE_64, 1, false, 1, "push" },
    /* 0x6B: IMUL r, r/m, imm8 */
    [0x6B] = { X86_OP_IMUL, X86_CAT_ARITHMETIC, ENC_MODRM_REG, SIZE_32, 3, true, 1, "imul" },

    /* 0x70-0x7F: Jcc rel8 */
    [0x70] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jo" },
    [0x71] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jno" },
    [0x72] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jb" },
    [0x73] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jae" },
    [0x74] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "je" },
    [0x75] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jne" },
    [0x76] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jbe" },
    [0x77] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "ja" },
    [0x78] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "js" },
    [0x79] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jns" },
    [0x7A] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jp" },
    [0x7B] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jnp" },
    [0x7C] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jl" },
    [0x7D] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jge" },
    [0x7E] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jle" },
    [0x7F] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jg" },

    /* 0x80: Group 1 r/m8, imm8 */
    [0x80] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8, 2, true, 1, "grp1" },
    /* 0x81: Group 1 r/m, imm32 */
    [0x81] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 2, true, 4, "grp1" },
    /* 0x82: alias of 0x80 in 32-bit mode, invalid in 64-bit */
    /* 0x83: Group 1 r/m, imm8 (sign-extended) */
    [0x83] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 2, true, 1, "grp1" },

    /* 0x84-0x85: TEST */
    [0x84] = { X86_OP_TEST, X86_CAT_LOGIC, ENC_MODRM_REG, SIZE_8,  2, true, 0, "test" },
    [0x85] = { X86_OP_TEST, X86_CAT_LOGIC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "test" },

    /* 0x86-0x87: XCHG */
    [0x86] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_8,  2, true, 0, "xchg" },
    [0x87] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_32, 2, true, 0, "xchg" },

    /* 0x88-0x8B: MOV */
    [0x88] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_8,  2, true, 0, "mov" },
    [0x89] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_32, 2, true, 0, "mov" },
    [0x8A] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_8,  2, true, 0, "mov" },
    [0x8B] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_32, 2, true, 0, "mov" },

    /* 0x8D: LEA */
    [0x8D] = { X86_OP_LEA, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_32, 2, true, 0, "lea" },

    /* 0x8F: POP r/m (group - reg=0 is POP) */
    [0x8F] = { X86_OP_POP, X86_CAT_DATA_XFER, ENC_MODRM_RM, SIZE_64, 1, true, 0, "pop" },

    /* 0x90: NOP (XCHG rAX, rAX) */
    [0x90] = { X86_OP_NOP, X86_CAT_NOP, ENC_FIXED, SIZE_32, 0, false, 0, "nop" },

    /* 0x91-0x97: XCHG rAX, reg */
    [0x91] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x92] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x93] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x94] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x95] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x96] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },
    [0x97] = { X86_OP_XCHG, X86_CAT_DATA_XFER, ENC_REG_ONLY, SIZE_32, 2, false, 0, "xchg" },

    /* 0x98: CBW/CWDE/CDQE */
    [0x98] = { X86_OP_CWDE, X86_CAT_DATA_XFER, ENC_FIXED, SIZE_32, 0, false, 0, "cwde" },
    /* 0x99: CWD/CDQ/CQO */
    [0x99] = { X86_OP_CDQ, X86_CAT_DATA_XFER, ENC_FIXED, SIZE_32, 0, false, 0, "cdq" },

    /* 0xA8-0xA9: TEST AL/rAX, imm */
    [0xA8] = { X86_OP_TEST, X86_CAT_LOGIC, ENC_ACC_IMM, SIZE_8,  2, false, 1, "test" },
    [0xA9] = { X86_OP_TEST, X86_CAT_LOGIC, ENC_ACC_IMM, SIZE_32, 2, false, 4, "test" },

    /* 0xB0-0xB7: MOV r8, imm8 */
    [0xB0] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB1] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB2] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB3] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB4] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB5] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB6] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },
    [0xB7] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_8, 2, false, 1, "mov" },

    /* 0xB8-0xBF: MOV r64, imm64 (or r32, imm32 without REX.W) */
    [0xB8] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xB9] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBA] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBB] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBC] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBD] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBE] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },
    [0xBF] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_REG_IMM, SIZE_32, 2, false, 4, "mov" },

    /* 0xC0-0xC1: Group 2 shifts with imm8 */
    [0xC0] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8,  2, true, 1, "grp2" },
    [0xC1] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 2, true, 1, "grp2" },

    /* 0xC3: RET */
    [0xC3] = { X86_OP_RET, X86_CAT_CONTROL, ENC_FIXED, SIZE_64, 0, false, 0, "ret" },

    /* 0xC6: MOV r/m8, imm8 (group 11, reg=0 is MOV) */
    [0xC6] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_RM, SIZE_8,  2, true, 1, "mov" },
    /* 0xC7: MOV r/m, imm32 (group 11, reg=0 is MOV) */
    [0xC7] = { X86_OP_MOV, X86_CAT_DATA_XFER, ENC_MODRM_RM, SIZE_32, 2, true, 4, "mov" },

    /* 0xD0-0xD1: Group 2 shifts by 1 */
    [0xD0] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8,  2, true, 0, "grp2" },
    [0xD1] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 2, true, 0, "grp2" },

    /* 0xD2-0xD3: Group 2 shifts by CL */
    [0xD2] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8,  2, true, 0, "grp2" },
    [0xD3] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 2, true, 0, "grp2" },

    /* 0xE8: CALL rel32 */
    [0xE8] = { X86_OP_CALL, X86_CAT_CONTROL, ENC_REL32, SIZE_64, 1, false, 4, "call" },

    /* 0xE9: JMP rel32 */
    [0xE9] = { X86_OP_JMP, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jmp" },

    /* 0xEB: JMP rel8 */
    [0xEB] = { X86_OP_JMP, X86_CAT_CONTROL, ENC_REL8, SIZE_32, 1, false, 1, "jmp" },

    /* 0xF0: LOCK prefix */
    [0xF0] = PREFIX_ENTRY("lock"),
    /* 0xF2: REPNE prefix */
    [0xF2] = PREFIX_ENTRY("repne"),
    /* 0xF3: REP prefix */
    [0xF3] = PREFIX_ENTRY("rep"),

    /* 0xF6: Group 3 byte */
    [0xF6] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8,  1, true, 0, "grp3" },
    /* 0xF7: Group 3 word/dword/qword */
    [0xF7] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 1, true, 0, "grp3" },

    /* 0xFE: Group 4 - INC/DEC byte */
    [0xFE] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_8,  1, true, 0, "grp4" },

    /* 0xFF: Group 5 - INC/DEC/CALL/JMP/PUSH */
    [0xFF] = { X86_OP_INVALID, X86_CAT_INVALID, ENC_GROUP, SIZE_32, 1, true, 0, "grp5" },
};

/*
 * Two-byte opcode table (0F xx, 256 entries)
 */
const opcode_entry_t opcode_table_2byte[256] = {
    /* 0x0F 0x05: SYSCALL */
    [0x05] = { X86_OP_SYSCALL, X86_CAT_SYSTEM, ENC_FIXED, SIZE_64, 0, false, 0, "syscall" },

    /* 0x0F 0x10: MOVUPS xmm, xmm/m128 (with F3 = MOVSS, F2 = MOVSD) */
    [0x10] = { X86_OP_MOVUPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "movups" },
    /* 0x0F 0x11: MOVUPS xmm/m128, xmm */
    [0x11] = { X86_OP_MOVUPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "movups" },

    /* 0x0F 0x1F: multi-byte NOP */
    [0x1F] = { X86_OP_NOP, X86_CAT_NOP, ENC_MODRM_RM, SIZE_32, 0, true, 0, "nop" },

    /* 0x0F 0x28-0x29: MOVAPS */
    [0x28] = { X86_OP_MOVAPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "movaps" },
    [0x29] = { X86_OP_MOVAPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "movaps" },

    /* 0x0F 0x2E: UCOMISS */
    [0x2E] = { X86_OP_UCOMISS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "ucomiss" },
    /* 0x0F 0x2F: COMISS (treat as UCOMISS) */
    [0x2F] = { X86_OP_UCOMISS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "comiss" },

    /* 0x0F 0x40-0x4F: CMOVcc */
    [0x40] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovo" },
    [0x41] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovno" },
    [0x42] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovb" },
    [0x43] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovae" },
    [0x44] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmove" },
    [0x45] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovne" },
    [0x46] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovbe" },
    [0x47] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmova" },
    [0x48] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovs" },
    [0x49] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovns" },
    [0x4A] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovp" },
    [0x4B] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovnp" },
    [0x4C] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovl" },
    [0x4D] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovge" },
    [0x4E] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovle" },
    [0x4F] = { X86_OP_CMOVCC, X86_CAT_CMOVCC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "cmovg" },

    /* 0x0F 0x51: SQRTPS (F3=SQRTSS, F2=SQRTSD) */
    [0x51] = { X86_OP_SQRTSS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "sqrtps" },

    /* 0x0F 0x54: ANDPS */
    [0x54] = { X86_OP_ANDPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "andps" },

    /* 0x0F 0x56: ORPS */
    [0x56] = { X86_OP_ORPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "orps" },

    /* 0x0F 0x57: XORPS */
    [0x57] = { X86_OP_XORPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "xorps" },

    /* 0x0F 0x58: ADDPS (F3=ADDSS, F2=ADDSD) */
    [0x58] = { X86_OP_ADDPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "addps" },

    /* 0x0F 0x59: MULPS (F3=MULSS, F2=MULSD) */
    [0x59] = { X86_OP_MULPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "mulps" },

    /* 0x0F 0x5C: SUBPS (F3=SUBSS, F2=SUBSD) */
    [0x5C] = { X86_OP_SUBPS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "subps" },

    /* 0x0F 0x5E: DIVPS (F3=DIVSS, F2=DIVSD) */
    [0x5E] = { X86_OP_DIVSS, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "divps" },

    /* 0x0F 0x80-0x8F: Jcc rel32 */
    [0x80] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jo" },
    [0x81] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jno" },
    [0x82] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jb" },
    [0x83] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jae" },
    [0x84] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "je" },
    [0x85] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jne" },
    [0x86] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jbe" },
    [0x87] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "ja" },
    [0x88] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "js" },
    [0x89] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jns" },
    [0x8A] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jp" },
    [0x8B] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jnp" },
    [0x8C] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jl" },
    [0x8D] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jge" },
    [0x8E] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jle" },
    [0x8F] = { X86_OP_JCC, X86_CAT_CONTROL, ENC_REL32, SIZE_32, 1, false, 4, "jg" },

    /* 0x0F 0x90-0x9F: SETcc */
    [0x90] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "seto" },
    [0x91] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setno" },
    [0x92] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setb" },
    [0x93] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setae" },
    [0x94] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "sete" },
    [0x95] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setne" },
    [0x96] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setbe" },
    [0x97] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "seta" },
    [0x98] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "sets" },
    [0x99] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setns" },
    [0x9A] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setp" },
    [0x9B] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setnp" },
    [0x9C] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setl" },
    [0x9D] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setge" },
    [0x9E] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setle" },
    [0x9F] = { X86_OP_SETCC, X86_CAT_SETCC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "setg" },

    /* 0x0F 0xAF: IMUL r, r/m */
    [0xAF] = { X86_OP_IMUL, X86_CAT_ARITHMETIC, ENC_MODRM_REG, SIZE_32, 2, true, 0, "imul" },

    /* 0x0F 0xB6: MOVZX r, r/m8 */
    [0xB6] = { X86_OP_MOVZX, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_8, 2, true, 0, "movzx" },
    /* 0x0F 0xB7: MOVZX r, r/m16 */
    [0xB7] = { X86_OP_MOVZX, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_16, 2, true, 0, "movzx" },

    /* 0x0F 0xBE: MOVSX r, r/m8 */
    [0xBE] = { X86_OP_MOVSX, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_8, 2, true, 0, "movsx" },
    /* 0x0F 0xBF: MOVSX r, r/m16 */
    [0xBF] = { X86_OP_MOVSX, X86_CAT_DATA_XFER, ENC_MODRM_REG, SIZE_16, 2, true, 0, "movsx" },

    /* 0x0F 0xEF: PXOR */
    [0xEF] = { X86_OP_PXOR, X86_CAT_SSE, ENC_MODRM_REG, SIZE_32, 2, true, 0, "pxor" },
};

/*
 * Group 1: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP
 * Used by opcodes 0x80, 0x81, 0x83
 */
const opcode_entry_t group1_table[8] = {
    [0] = { X86_OP_ADD, X86_CAT_ARITHMETIC, ENC_MODRM_RM, SIZE_32, 2, true, 0, "add" },
    [1] = { X86_OP_OR,  X86_CAT_LOGIC,      ENC_MODRM_RM, SIZE_32, 2, true, 0, "or"  },
    [2] = { X86_OP_ADC, X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 2, true, 0, "adc" },
    [3] = { X86_OP_SBB, X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 2, true, 0, "sbb" },
    [4] = { X86_OP_AND, X86_CAT_LOGIC,       ENC_MODRM_RM, SIZE_32, 2, true, 0, "and" },
    [5] = { X86_OP_SUB, X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 2, true, 0, "sub" },
    [6] = { X86_OP_XOR, X86_CAT_LOGIC,       ENC_MODRM_RM, SIZE_32, 2, true, 0, "xor" },
    [7] = { X86_OP_CMP, X86_CAT_COMPARE,     ENC_MODRM_RM, SIZE_32, 2, true, 0, "cmp" },
};

/*
 * Group 2: ROL, ROR, RCL, RCR, SHL, SHR, SAL(=SHL), SAR
 * Used by opcodes 0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3
 */
const opcode_entry_t group2_table[8] = {
    [0] = { X86_OP_ROL, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "rol" },
    [1] = { X86_OP_ROR, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "ror" },
    [2] = { X86_OP_RCL, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "rcl" },
    [3] = { X86_OP_RCR, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "rcr" },
    [4] = { X86_OP_SHL, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "shl" },
    [5] = { X86_OP_SHR, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "shr" },
    [6] = { X86_OP_SHL, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "sal" },
    [7] = { X86_OP_SAR, X86_CAT_SHIFT, ENC_MODRM_RM, SIZE_32, 2, true, 0, "sar" },
};

/*
 * Group 3: TEST, -, NOT, NEG, MUL, IMUL, DIV, IDIV
 * Used by opcodes 0xF6, 0xF7
 * NOTE: reg=0 (TEST) has an immediate operand; others don't
 */
const opcode_entry_t group3_table[8] = {
    [0] = { X86_OP_TEST, X86_CAT_LOGIC,      ENC_MODRM_RM, SIZE_32, 2, true, 0, "test" },
    [1] = { X86_OP_INVALID, X86_CAT_INVALID,  ENC_NONE,     SIZE_32, 0, true, 0, NULL   },
    [2] = { X86_OP_NOT,  X86_CAT_LOGIC,       ENC_MODRM_RM, SIZE_32, 1, true, 0, "not"  },
    [3] = { X86_OP_NEG,  X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 1, true, 0, "neg"  },
    [4] = { X86_OP_MUL,  X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 1, true, 0, "mul"  },
    [5] = { X86_OP_IMUL, X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 1, true, 0, "imul" },
    [6] = { X86_OP_DIV,  X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 1, true, 0, "div"  },
    [7] = { X86_OP_IDIV, X86_CAT_ARITHMETIC,  ENC_MODRM_RM, SIZE_32, 1, true, 0, "idiv" },
};

/*
 * Group 4: INC, DEC (byte)
 * Used by opcode 0xFE
 */
const opcode_entry_t group4_table[8] = {
    [0] = { X86_OP_INC, X86_CAT_ARITHMETIC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "inc" },
    [1] = { X86_OP_DEC, X86_CAT_ARITHMETIC, ENC_MODRM_RM, SIZE_8, 1, true, 0, "dec" },
    [2] = INVALID_ENTRY,
    [3] = INVALID_ENTRY,
    [4] = INVALID_ENTRY,
    [5] = INVALID_ENTRY,
    [6] = INVALID_ENTRY,
    [7] = INVALID_ENTRY,
};

/*
 * Group 5: INC, DEC, CALL, -, JMP, -, PUSH, -
 * Used by opcode 0xFF
 */
const opcode_entry_t group5_table[8] = {
    [0] = { X86_OP_INC,  X86_CAT_ARITHMETIC, ENC_MODRM_RM, SIZE_32, 1, true, 0, "inc"  },
    [1] = { X86_OP_DEC,  X86_CAT_ARITHMETIC, ENC_MODRM_RM, SIZE_32, 1, true, 0, "dec"  },
    [2] = { X86_OP_CALL, X86_CAT_CONTROL,    ENC_MODRM_RM, SIZE_64, 1, true, 0, "call" },
    [3] = INVALID_ENTRY,
    [4] = { X86_OP_JMP,  X86_CAT_CONTROL,    ENC_MODRM_RM, SIZE_64, 1, true, 0, "jmp"  },
    [5] = INVALID_ENTRY,
    [6] = { X86_OP_PUSH, X86_CAT_DATA_XFER,  ENC_MODRM_RM, SIZE_64, 1, true, 0, "push" },
    [7] = INVALID_ENTRY,
};

void x86_tables_init(void)
{
    /* Tables are const-initialized; nothing to do at runtime */
}

const opcode_entry_t *x86_lookup_1byte(uint8_t opcode)
{
    return &opcode_table_1byte[opcode];
}

const opcode_entry_t *x86_lookup_2byte(uint8_t opcode)
{
    return &opcode_table_2byte[opcode];
}

const opcode_entry_t *x86_lookup_group(int group, uint8_t reg)
{
    reg &= 7;
    switch (group) {
    case 1:  return &group1_table[reg];
    case 2:  return &group2_table[reg];
    case 3:  return &group3_table[reg];
    case 4:  return &group4_table[reg];
    case 5:  return &group5_table[reg];
    default: return NULL;
    }
}
