/*
 * x86_tables.h - Opcode lookup tables for x86_64 decoding
 */

#ifndef X86_TABLES_H
#define X86_TABLES_H

#include "alt_rosetta.h"
#include "x86_decode.h"

/* How to decode operands for an opcode table entry */
typedef enum {
    ENC_NONE = 0,       /* No operands */
    ENC_MODRM_REG,      /* ModR/M: reg field is the register, rm is r/m */
    ENC_MODRM_RM,       /* ModR/M: rm field only (reg is opcode extension) */
    ENC_REG_IMM,        /* Register in low 3 bits of opcode + immediate */
    ENC_ACC_IMM,        /* AL/AX/EAX/RAX + immediate */
    ENC_REL8,           /* 8-bit relative offset */
    ENC_REL32,          /* 32-bit relative offset */
    ENC_FIXED,          /* Fixed encoding (no operands or implicit) */
    ENC_REG_ONLY,       /* Register in low 3 bits of opcode */
    ENC_PREFIX,         /* This byte is a prefix */
    ENC_ESCAPE,         /* Escape to 2-byte table (0x0F) */
    ENC_GROUP,          /* Group: modrm.reg selects sub-opcode */
} encoding_type_t;

/* Opcode table entry */
typedef struct {
    x86_op_type_t   op;             /* Instruction type */
    x86_category_t  category;       /* Category */
    encoding_type_t encoding;       /* How to decode operands */
    operand_size_t  default_size;   /* Default operand size */
    uint8_t         num_operands;   /* Number of operands */
    bool            has_modrm;      /* Requires ModR/M byte */
    uint8_t         imm_size;       /* Immediate size in bytes (0=none, 1/2/4/8) */
    const char     *mnemonic;       /* Mnemonic string */
} opcode_entry_t;

/* One-byte opcode table (256 entries) */
extern const opcode_entry_t opcode_table_1byte[256];

/* Two-byte opcode table (0F xx, 256 entries) */
extern const opcode_entry_t opcode_table_2byte[256];

/* Group tables - indexed by modrm.reg field (0-7) */
extern const opcode_entry_t group1_table[8];   /* 80-83: ADD/OR/ADC/SBB/AND/SUB/XOR/CMP */
extern const opcode_entry_t group2_table[8];   /* C0/D0/D2: ROL/ROR/RCL/RCR/SHL/SHR/SAL/SAR */
extern const opcode_entry_t group3_table[8];   /* F6/F7: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV */
extern const opcode_entry_t group4_table[8];   /* FE: INC/DEC (byte) */
extern const opcode_entry_t group5_table[8];   /* FF: INC/DEC/CALL/JMP/PUSH */

/* Initialize tables (called once at startup) */
void x86_tables_init(void);

/* Look up a one-byte opcode */
const opcode_entry_t *x86_lookup_1byte(uint8_t opcode);

/* Look up a two-byte opcode (after 0F prefix) */
const opcode_entry_t *x86_lookup_2byte(uint8_t opcode);

/* Look up a group opcode by group number and reg field */
const opcode_entry_t *x86_lookup_group(int group, uint8_t reg);

#endif /* X86_TABLES_H */
