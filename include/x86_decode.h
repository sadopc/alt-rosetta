/*
 * x86_decode.h - x86_64 instruction decoder
 *
 * Decodes variable-length x86_64 instructions into a structured representation.
 * Handles prefixes, REX, ModR/M, SIB, displacements, and immediates.
 */

#ifndef X86_DECODE_H
#define X86_DECODE_H

#include "alt_rosetta.h"

/* Maximum x86 instruction length */
#define X86_MAX_INSTR_LEN 15

/* Instruction categories (high-level) */
typedef enum {
    X86_CAT_INVALID = 0,
    X86_CAT_DATA_XFER,     /* MOV, LEA, PUSH, POP, XCHG, MOVZX, MOVSX, CDQ, CQO */
    X86_CAT_ARITHMETIC,    /* ADD, SUB, ADC, SBB, INC, DEC, NEG, MUL, IMUL, DIV, IDIV */
    X86_CAT_LOGIC,         /* AND, OR, XOR, NOT, TEST */
    X86_CAT_SHIFT,         /* SHL, SHR, SAR, ROL, ROR, RCL, RCR */
    X86_CAT_CONTROL,       /* JMP, Jcc, CALL, RET, LOOP */
    X86_CAT_COMPARE,       /* CMP (like SUB but discard result) */
    X86_CAT_SETCC,         /* SETcc */
    X86_CAT_CMOVCC,        /* CMOVcc */
    X86_CAT_STRING,        /* REP MOVSB, REP STOSB, etc. */
    X86_CAT_SYSTEM,        /* SYSCALL, INT, HLT */
    X86_CAT_SSE,           /* SSE/SSE2 instructions */
    X86_CAT_NOP,           /* NOP, multi-byte NOP */
    X86_CAT_FLAG_MANIP,    /* CLC, STC, CLD, STD, CMC */
    X86_CAT_MISC,          /* CPUID, RDTSC, etc. */
} x86_category_t;

/* Specific instruction types */
typedef enum {
    X86_OP_INVALID = 0,

    /* Data transfer */
    X86_OP_MOV, X86_OP_MOVZX, X86_OP_MOVSX, X86_OP_MOVSXD,
    X86_OP_LEA, X86_OP_PUSH, X86_OP_POP,
    X86_OP_XCHG, X86_OP_CDQ, X86_OP_CQO, X86_OP_CBW, X86_OP_CWDE, X86_OP_CDQE,

    /* Arithmetic */
    X86_OP_ADD, X86_OP_SUB, X86_OP_ADC, X86_OP_SBB,
    X86_OP_INC, X86_OP_DEC, X86_OP_NEG, X86_OP_NOT,
    X86_OP_MUL, X86_OP_IMUL, X86_OP_DIV, X86_OP_IDIV,

    /* Logic */
    X86_OP_AND, X86_OP_OR, X86_OP_XOR, X86_OP_TEST,

    /* Compare */
    X86_OP_CMP,

    /* Shifts/rotates */
    X86_OP_SHL, X86_OP_SHR, X86_OP_SAR,
    X86_OP_ROL, X86_OP_ROR, X86_OP_RCL, X86_OP_RCR,

    /* Control flow */
    X86_OP_JMP, X86_OP_JCC, X86_OP_CALL, X86_OP_RET,
    X86_OP_LOOP, X86_OP_LOOPE, X86_OP_LOOPNE,

    /* Conditional set/move */
    X86_OP_SETCC, X86_OP_CMOVCC,

    /* String operations */
    X86_OP_MOVSB, X86_OP_MOVSW, X86_OP_MOVSD_STR, X86_OP_MOVSQ,
    X86_OP_STOSB, X86_OP_STOSW, X86_OP_STOSD, X86_OP_STOSQ,
    X86_OP_LODSB, X86_OP_LODSW, X86_OP_LODSD, X86_OP_LODSQ,
    X86_OP_CMPSB, X86_OP_SCASB,

    /* System */
    X86_OP_SYSCALL, X86_OP_INT, X86_OP_HLT,
    X86_OP_CPUID, X86_OP_RDTSC,

    /* Flag manipulation */
    X86_OP_CLC, X86_OP_STC, X86_OP_CLD, X86_OP_STD, X86_OP_CMC,

    /* SSE scalar */
    X86_OP_MOVSS, X86_OP_MOVSD, X86_OP_MOVAPS, X86_OP_MOVUPS,
    X86_OP_ADDSS, X86_OP_ADDSD, X86_OP_SUBSS, X86_OP_SUBSD,
    X86_OP_MULSS, X86_OP_MULSD, X86_OP_DIVSS, X86_OP_DIVSD,
    X86_OP_SQRTSS, X86_OP_SQRTSD,
    X86_OP_UCOMISS, X86_OP_UCOMISD,
    X86_OP_CVTSI2SS, X86_OP_CVTSI2SD,
    X86_OP_CVTSS2SI, X86_OP_CVTSD2SI,
    X86_OP_CVTSS2SD, X86_OP_CVTSD2SS,
    X86_OP_XORPS, X86_OP_XORPD,
    X86_OP_ANDPS, X86_OP_ORPS,
    X86_OP_PXOR,

    /* SSE packed */
    X86_OP_ADDPS, X86_OP_ADDPD, X86_OP_SUBPS, X86_OP_SUBPD,
    X86_OP_MULPS, X86_OP_MULPD,
    X86_OP_PADDB, X86_OP_PADDW, X86_OP_PADDD, X86_OP_PADDQ,

    /* NOP */
    X86_OP_NOP,

    X86_OP_COUNT
} x86_op_type_t;

/* x86 condition codes (for Jcc, SETcc, CMOVcc) */
typedef enum {
    X86_CC_O   = 0x0,  /* Overflow */
    X86_CC_NO  = 0x1,  /* Not overflow */
    X86_CC_B   = 0x2,  /* Below (CF=1) */
    X86_CC_AE  = 0x3,  /* Above or equal (CF=0) */
    X86_CC_E   = 0x4,  /* Equal (ZF=1) */
    X86_CC_NE  = 0x5,  /* Not equal (ZF=0) */
    X86_CC_BE  = 0x6,  /* Below or equal (CF=1 or ZF=1) */
    X86_CC_A   = 0x7,  /* Above (CF=0 and ZF=0) */
    X86_CC_S   = 0x8,  /* Sign (SF=1) */
    X86_CC_NS  = 0x9,  /* Not sign (SF=0) */
    X86_CC_P   = 0xA,  /* Parity (PF=1) */
    X86_CC_NP  = 0xB,  /* Not parity (PF=0) */
    X86_CC_L   = 0xC,  /* Less (SF≠OF) */
    X86_CC_GE  = 0xD,  /* Greater or equal (SF=OF) */
    X86_CC_LE  = 0xE,  /* Less or equal (ZF=1 or SF≠OF) */
    X86_CC_G   = 0xF,  /* Greater (ZF=0 and SF=OF) */
} x86_cc_t;

/* Operand types */
typedef enum {
    OPERAND_NONE = 0,
    OPERAND_REG,        /* Register */
    OPERAND_IMM,        /* Immediate value */
    OPERAND_MEM,        /* Memory reference [base + index*scale + disp] */
    OPERAND_REL,        /* RIP-relative offset (for branches) */
} operand_type_t;

/* A single operand */
typedef struct {
    operand_type_t type;
    operand_size_t size;    /* Operand size in bytes */

    union {
        /* Register operand */
        struct {
            uint8_t reg;    /* Register index (0-15) */
        } reg;

        /* Immediate operand */
        struct {
            int64_t value;
        } imm;

        /* Memory operand: [base + index*scale + disp] */
        struct {
            int8_t   base;      /* Base register (-1 = none) */
            int8_t   index;     /* Index register (-1 = none) */
            uint8_t  scale;     /* 1, 2, 4, or 8 */
            int64_t  disp;      /* Displacement */
            bool     rip_rel;   /* RIP-relative addressing */
        } mem;

        /* Relative offset (for branches) */
        struct {
            int64_t offset;     /* Signed offset from next instruction */
        } rel;
    };
} x86_operand_t;

/* Decoded x86_64 instruction */
struct x86_instr {
    /* Address and raw bytes */
    uint64_t    addr;
    uint8_t     bytes[X86_MAX_INSTR_LEN];
    uint8_t     length;

    /* Classification */
    x86_category_t category;
    x86_op_type_t  op;

    /* For conditional instructions */
    x86_cc_t    cc;

    /* Prefix state */
    bool        has_rex;
    uint8_t     rex;            /* Raw REX byte */
    bool        rex_w;          /* 64-bit operand size */
    bool        rex_r;          /* ModR/M reg extension */
    bool        rex_x;          /* SIB index extension */
    bool        rex_b;          /* ModR/M rm / SIB base extension */
    bool        has_lock;       /* LOCK prefix (F0) */
    bool        has_rep;        /* REP/REPE prefix (F3) */
    bool        has_repne;      /* REPNE prefix (F2) */
    bool        has_66;         /* Operand size override (66) */
    bool        has_67;         /* Address size override (67) */
    uint8_t     seg_override;   /* Segment override (0 = none) */

    /* Operand size for this instruction */
    operand_size_t op_size;

    /* Operands (up to 3) */
    x86_operand_t operands[3];
    int         num_operands;

    /* ModR/M fields (if present) */
    bool        has_modrm;
    uint8_t     modrm;
    uint8_t     modrm_mod;
    uint8_t     modrm_reg;      /* /r field (with REX.R) */
    uint8_t     modrm_rm;       /* R/M field (with REX.B) */

    /* SIB fields (if present) */
    bool        has_sib;
    uint8_t     sib;
    uint8_t     sib_scale;
    uint8_t     sib_index;
    uint8_t     sib_base;
};

/* Decode one x86_64 instruction at the given address.
 * Returns the number of bytes consumed, or 0 on error. */
int x86_decode(const uint8_t *code, size_t max_len, uint64_t addr, x86_instr_t *instr);

/* Format a decoded instruction as a human-readable string.
 * Returns a pointer to a static buffer. */
const char *x86_format_instr(const x86_instr_t *instr);

/* Get the string name for an x86 condition code */
const char *x86_cc_name(x86_cc_t cc);

/* Check if an instruction is a basic block terminator */
bool x86_is_block_terminator(const x86_instr_t *instr);

/* Check if an instruction reads flags */
bool x86_reads_flags(const x86_instr_t *instr);

/* Check if an instruction writes flags */
bool x86_writes_flags(const x86_instr_t *instr);

#endif /* X86_DECODE_H */
