/*
 * x86_decode.c - x86_64 instruction decoder
 *
 * Decodes variable-length x86_64 instructions into a structured representation.
 * Handles prefixes, REX, ModR/M, SIB, displacements, and immediates.
 */

#include "x86_decode.h"
#include "x86_tables.h"

/* Register name tables */
static const char *reg_names_64[16] = {
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
};

static const char *reg_names_32[16] = {
    "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d"
};

static const char *reg_names_16[16] = {
    "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",
    "r8w", "r9w", "r10w","r11w","r12w","r13w","r14w","r15w"
};

static const char *reg_names_8[16] = {
    "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil",
    "r8b", "r9b", "r10b","r11b","r12b","r13b","r14b","r15b"
};

static const char *reg_names_8_norex[8] = {
    "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"
};

static const char *cc_names[16] = {
    "o", "no", "b", "ae", "e", "ne", "be", "a",
    "s", "ns", "p", "np", "l", "ge", "le", "g"
};

/* Read bytes with bounds checking */
static inline bool has_bytes(size_t offset, size_t need, size_t max_len)
{
    return (offset + need) <= max_len;
}

static inline uint8_t read_u8(const uint8_t *code, size_t *offset)
{
    return code[(*offset)++];
}

static inline int8_t read_i8(const uint8_t *code, size_t *offset)
{
    return (int8_t)code[(*offset)++];
}

static inline uint32_t read_u32(const uint8_t *code, size_t *offset)
{
    uint32_t val = (uint32_t)code[*offset]
                 | ((uint32_t)code[*offset + 1] << 8)
                 | ((uint32_t)code[*offset + 2] << 16)
                 | ((uint32_t)code[*offset + 3] << 24);
    *offset += 4;
    return val;
}

static inline int32_t read_i32(const uint8_t *code, size_t *offset)
{
    return (int32_t)read_u32(code, offset);
}

static inline uint64_t read_u64(const uint8_t *code, size_t *offset)
{
    uint64_t lo = read_u32(code, offset);
    uint64_t hi = read_u32(code, offset);
    return lo | (hi << 32);
}

static inline uint16_t read_u16(const uint8_t *code, size_t *offset)
{
    uint16_t val = (uint16_t)code[*offset]
                 | ((uint16_t)code[*offset + 1] << 8);
    *offset += 2;
    return val;
}

/*
 * Determine which group number an opcode belongs to.
 * Returns 0 if not a group instruction.
 */
static int get_group_number(uint8_t primary_opcode, bool is_2byte)
{
    if (is_2byte)
        return 0;

    switch (primary_opcode) {
    case 0x80: case 0x81: case 0x83:
        return 1;
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3:
        return 2;
    case 0xF6: case 0xF7:
        return 3;
    case 0xFE:
        return 4;
    case 0xFF:
        return 5;
    default:
        return 0;
    }
}

/*
 * Determine operand size based on prefix state and default.
 * In 64-bit mode:
 *   - REX.W=1 -> 64-bit
 *   - 66 prefix -> 16-bit
 *   - default -> 32-bit (with zero extension to 64)
 * Some instructions (PUSH/POP/CALL/RET) default to 64-bit.
 */
static operand_size_t determine_op_size(const x86_instr_t *instr,
                                         operand_size_t default_size)
{
    if (instr->rex_w)
        return SIZE_64;

    /* Instructions that default to 64-bit in long mode */
    if (default_size == SIZE_64)
        return SIZE_64;

    if (instr->has_66)
        return SIZE_16;

    return default_size;
}

static const char *reg_name(uint8_t reg, operand_size_t size, bool has_rex)
{
    switch (size) {
    case SIZE_64: return reg_names_64[reg & 0xF];
    case SIZE_32: return reg_names_32[reg & 0xF];
    case SIZE_16: return reg_names_16[reg & 0xF];
    case SIZE_8:
        if (has_rex || reg >= 8)
            return reg_names_8[reg & 0xF];
        return reg_names_8_norex[reg & 7];
    default:
        return "???";
    }
}

/*
 * Build a register operand.
 */
static void build_reg_operand(x86_operand_t *op, uint8_t reg, operand_size_t size)
{
    op->type = OPERAND_REG;
    op->size = size;
    op->reg.reg = reg;
}

/*
 * Build an immediate operand.
 */
static void build_imm_operand(x86_operand_t *op, int64_t value, operand_size_t size)
{
    op->type = OPERAND_IMM;
    op->size = size;
    op->imm.value = value;
}

/*
 * Build a relative offset operand.
 */
static void build_rel_operand(x86_operand_t *op, int64_t offset)
{
    op->type = OPERAND_REL;
    op->size = SIZE_64;
    op->rel.offset = offset;
}

/*
 * Decode ModR/M + SIB + displacement into a memory operand.
 */
static void decode_memory_operand(x86_operand_t *op, const x86_instr_t *instr,
                                  operand_size_t size)
{
    op->type = OPERAND_MEM;
    op->size = size;
    op->mem.base = -1;
    op->mem.index = -1;
    op->mem.scale = 1;
    op->mem.disp = 0;
    op->mem.rip_rel = false;

    uint8_t mod = instr->modrm_mod;
    uint8_t rm = instr->modrm_rm;

    if (mod == 3) {
        /* Register direct - not a memory operand, caller should use reg */
        op->type = OPERAND_REG;
        op->reg.reg = rm;
        return;
    }

    if (instr->has_sib) {
        /* SIB byte present */
        uint8_t base = instr->sib_base;
        uint8_t index = instr->sib_index;

        if (index != 4) { /* index=4 means no index (RSP can't be index) */
            op->mem.index = index;
            op->mem.scale = instr->sib_scale;
        }

        if (base == 5 && mod == 0) {
            /* [index*scale + disp32] or [disp32] */
            op->mem.base = -1;
        } else {
            op->mem.base = base;
        }
    } else if (mod == 0 && (rm & 7) == 5) {
        /* RIP-relative: [RIP + disp32] */
        op->mem.rip_rel = true;
    } else {
        op->mem.base = rm;
    }
}

int x86_decode(const uint8_t *code, size_t max_len, uint64_t addr, x86_instr_t *instr)
{
    if (!code || !instr || max_len == 0)
        return 0;

    memset(instr, 0, sizeof(*instr));
    instr->addr = addr;

    size_t offset = 0;

    /*
     * Phase 1: Prefix scanning
     * Scan for legacy prefixes and REX bytes.
     */
    bool done_prefix = false;
    while (!done_prefix && has_bytes(offset, 1, max_len)) {
        uint8_t b = code[offset];
        switch (b) {
        /* Operand size override */
        case 0x66:
            instr->has_66 = true;
            offset++;
            break;
        /* Address size override */
        case 0x67:
            instr->has_67 = true;
            offset++;
            break;
        /* LOCK */
        case 0xF0:
            instr->has_lock = true;
            offset++;
            break;
        /* REPNE/REPNZ */
        case 0xF2:
            instr->has_repne = true;
            instr->has_rep = false;
            offset++;
            break;
        /* REP/REPE/REPZ */
        case 0xF3:
            instr->has_rep = true;
            instr->has_repne = false;
            offset++;
            break;
        /* Segment overrides */
        case 0x26: instr->seg_override = 0x26; offset++; break;
        case 0x2E: instr->seg_override = 0x2E; offset++; break;
        case 0x36: instr->seg_override = 0x36; offset++; break;
        case 0x3E: instr->seg_override = 0x3E; offset++; break;
        case 0x64: instr->seg_override = 0x64; offset++; break;
        case 0x65: instr->seg_override = 0x65; offset++; break;
        default:
            /* Check for REX prefix (0x40-0x4F) */
            if (b >= 0x40 && b <= 0x4F) {
                instr->has_rex = true;
                instr->rex = b;
                instr->rex_w = (b >> 3) & 1;
                instr->rex_r = (b >> 2) & 1;
                instr->rex_x = (b >> 1) & 1;
                instr->rex_b = b & 1;
                offset++;
            } else {
                done_prefix = true;
            }
            break;
        }
    }

    if (!has_bytes(offset, 1, max_len))
        return 0;

    /*
     * Phase 2: Opcode read
     */
    uint8_t primary_opcode = read_u8(code, &offset);
    bool is_2byte = false;
    uint8_t secondary_opcode = 0;

    const opcode_entry_t *entry = x86_lookup_1byte(primary_opcode);

    if (entry->encoding == ENC_ESCAPE) {
        /* 0x0F escape to two-byte table */
        if (!has_bytes(offset, 1, max_len))
            return 0;
        secondary_opcode = read_u8(code, &offset);
        entry = x86_lookup_2byte(secondary_opcode);
        is_2byte = true;
    }

    if (entry->encoding == ENC_PREFIX) {
        /* Should have been consumed in prefix scan; bail */
        return 0;
    }

    /*
     * Phase 3: For group instructions, we need to peek at ModR/M to determine
     * the actual operation before we continue.
     */
    int group_num = 0;
    const opcode_entry_t *group_entry = NULL;

    if (entry->encoding == ENC_GROUP) {
        if (!has_bytes(offset, 1, max_len))
            return 0;

        uint8_t modrm_byte = code[offset]; /* peek, don't consume yet */
        uint8_t modrm_reg_field = (modrm_byte >> 3) & 7;

        group_num = get_group_number(primary_opcode, is_2byte);
        group_entry = x86_lookup_group(group_num, modrm_reg_field);

        if (!group_entry || group_entry->op == X86_OP_INVALID) {
            instr->op = X86_OP_INVALID;
            instr->category = X86_CAT_INVALID;
            instr->length = (uint8_t)offset;
            return 0;
        }
    }

    /* Use group entry if we have one, otherwise use the table entry */
    const opcode_entry_t *effective = group_entry ? group_entry : entry;

    instr->op = effective->op;
    instr->category = effective->category;

    /* Bail on invalid */
    if (instr->op == X86_OP_INVALID && entry->encoding != ENC_GROUP) {
        instr->length = (uint8_t)offset;
        return 0;
    }

    /*
     * Phase 4: Determine operand size
     */
    operand_size_t base_size = entry->default_size;
    /* For group instructions, use the parent opcode's default_size for byte vs word/dword */
    if (group_entry) {
        base_size = entry->default_size;
    }

    instr->op_size = determine_op_size(instr, base_size);

    /* Special: 0x98 - CBW/CWDE/CDQE depends on operand size */
    if (primary_opcode == 0x98 && !is_2byte) {
        if (instr->rex_w) {
            instr->op = X86_OP_CDQE;
        } else if (instr->has_66) {
            instr->op = X86_OP_CBW;
        } else {
            instr->op = X86_OP_CWDE;
        }
    }
    /* Special: 0x99 - CWD/CDQ/CQO depends on operand size */
    if (primary_opcode == 0x99 && !is_2byte) {
        if (instr->rex_w) {
            instr->op = X86_OP_CQO;
        } else if (instr->has_66) {
            instr->op = X86_OP_CDQ; /* CWD actually, but reuse CDQ */
        } else {
            instr->op = X86_OP_CDQ;
        }
    }

    /*
     * Phase 5: ModR/M decoding
     */
    bool need_modrm = entry->has_modrm || (group_entry != NULL);
    int32_t displacement = 0;

    if (need_modrm) {
        if (!has_bytes(offset, 1, max_len))
            return 0;

        uint8_t modrm_byte = read_u8(code, &offset);
        instr->has_modrm = true;
        instr->modrm = modrm_byte;
        instr->modrm_mod = (modrm_byte >> 6) & 3;
        instr->modrm_reg = ((modrm_byte >> 3) & 7) | (instr->rex_r ? 8 : 0);
        instr->modrm_rm  = (modrm_byte & 7) | (instr->rex_b ? 8 : 0);

        uint8_t raw_rm = modrm_byte & 7;
        uint8_t mod = instr->modrm_mod;

        /*
         * Phase 5a: SIB decoding
         * SIB is present when rm=4 (before REX extension) and mod != 3
         */
        if (raw_rm == 4 && mod != 3) {
            if (!has_bytes(offset, 1, max_len))
                return 0;

            uint8_t sib_byte = read_u8(code, &offset);
            instr->has_sib = true;
            instr->sib = sib_byte;
            instr->sib_scale = 1 << ((sib_byte >> 6) & 3);
            instr->sib_index = ((sib_byte >> 3) & 7) | (instr->rex_x ? 8 : 0);
            instr->sib_base  = (sib_byte & 7) | (instr->rex_b ? 8 : 0);

            /* Re-encode modrm_rm based on SIB for memory references */
            /* Keep modrm_rm as-is (4|REX.B) for SIB addressing */
        }

        /*
         * Phase 6: Displacement
         */
        if (mod == 1) {
            /* 8-bit displacement */
            if (!has_bytes(offset, 1, max_len))
                return 0;
            displacement = read_i8(code, &offset);
        } else if (mod == 2) {
            /* 32-bit displacement */
            if (!has_bytes(offset, 4, max_len))
                return 0;
            displacement = read_i32(code, &offset);
        } else if (mod == 0) {
            if (instr->has_sib) {
                /* SIB with mod=0: check if base=5 (disp32 with no base) */
                uint8_t raw_sib_base = instr->sib & 7;
                if (raw_sib_base == 5) {
                    if (!has_bytes(offset, 4, max_len))
                        return 0;
                    displacement = read_i32(code, &offset);
                }
            } else if (raw_rm == 5) {
                /* RIP-relative: disp32 */
                if (!has_bytes(offset, 4, max_len))
                    return 0;
                displacement = read_i32(code, &offset);
            }
        }
    }

    /*
     * Phase 7: Immediate value
     * Determine immediate size from the opcode entry.
     * Special cases: REX.W on MOV r, imm64 (0xB8-0xBF) upgrades to 8-byte imm.
     * Group 3 TEST has an immediate; other group 3 ops don't.
     */
    uint8_t imm_bytes = entry->imm_size;

    /* B8-BF: MOV r, imm32 normally, MOV r, imm64 with REX.W */
    if (!is_2byte && primary_opcode >= 0xB8 && primary_opcode <= 0xBF) {
        if (instr->rex_w)
            imm_bytes = 8;
    }

    /* Operand size override may change 4-byte imm to 2-byte for some opcodes */
    if (imm_bytes == 4 && instr->has_66 && !instr->rex_w) {
        /* But NOT for B8-BF (they're always imm32 or imm64) */
        if (is_2byte || !(primary_opcode >= 0xB8 && primary_opcode <= 0xBF)) {
            imm_bytes = 2;
        }
    }

    /* Group 3: TEST (reg=0) has an immediate, others don't */
    if (group_num == 3) {
        uint8_t grp_reg = (instr->modrm >> 3) & 7;
        if (grp_reg == 0) {
            /* TEST r/m, imm */
            if (entry->default_size == SIZE_8)
                imm_bytes = 1;
            else if (instr->rex_w || (!instr->has_66))
                imm_bytes = 4;
            else
                imm_bytes = 2;
        } else {
            imm_bytes = 0;
        }
    }

    int64_t imm_value = 0;
    if (imm_bytes > 0) {
        if (!has_bytes(offset, imm_bytes, max_len))
            return 0;

        switch (imm_bytes) {
        case 1:
            imm_value = read_i8(code, &offset);
            break;
        case 2:
            imm_value = (int16_t)read_u16(code, &offset);
            break;
        case 4:
            imm_value = read_i32(code, &offset);
            break;
        case 8:
            imm_value = (int64_t)read_u64(code, &offset);
            break;
        }
    }

    /* Store raw instruction bytes */
    instr->length = (uint8_t)offset;
    if (offset <= X86_MAX_INSTR_LEN)
        memcpy(instr->bytes, code, offset);
    else
        return 0;

    /*
     * Phase 8: Condition code extraction for Jcc, SETcc, CMOVcc
     */
    if (instr->op == X86_OP_JCC || instr->op == X86_OP_SETCC ||
        instr->op == X86_OP_CMOVCC) {
        uint8_t cc_opcode = is_2byte ? secondary_opcode : primary_opcode;
        instr->cc = (x86_cc_t)(cc_opcode & 0xF);
    }

    /*
     * Phase 9: Operand construction
     */
    instr->num_operands = 0;
    operand_size_t op_size = instr->op_size;

    /* SSE instructions: adjust for prefix-based SSE variant selection */
    if (is_2byte && effective->category == X86_CAT_SSE) {
        /* F3 prefix -> SS variant, F2 prefix -> SD variant */
        if (instr->has_rep) {
            switch (effective->op) {
            case X86_OP_MOVUPS: instr->op = X86_OP_MOVSS; break;
            case X86_OP_ADDPS:  instr->op = X86_OP_ADDSS; break;
            case X86_OP_MULPS:  instr->op = X86_OP_MULSS; break;
            case X86_OP_SUBPS:  instr->op = X86_OP_SUBSS; break;
            case X86_OP_DIVSS:  instr->op = X86_OP_DIVSS; break;
            case X86_OP_SQRTSS: instr->op = X86_OP_SQRTSS; break;
            default: break;
            }
        } else if (instr->has_repne) {
            switch (effective->op) {
            case X86_OP_MOVUPS: instr->op = X86_OP_MOVSD; break;
            case X86_OP_ADDPS:  instr->op = X86_OP_ADDSD; break;
            case X86_OP_MULPS:  instr->op = X86_OP_MULSD; break;
            case X86_OP_SUBPS:  instr->op = X86_OP_SUBSD; break;
            case X86_OP_DIVSS:  instr->op = X86_OP_DIVSD; break;
            case X86_OP_SQRTSS: instr->op = X86_OP_SQRTSD; break;
            default: break;
            }
        }
        /* 66 prefix -> PD variant for some ops (XORPS->XORPD, etc.) */
        if (instr->has_66) {
            switch (effective->op) {
            case X86_OP_XORPS:  instr->op = X86_OP_XORPD; break;
            case X86_OP_UCOMISS: instr->op = X86_OP_UCOMISD; break;
            default: break;
            }
        }
    }

    switch (entry->encoding) {
    case ENC_MODRM_REG: {
        /* reg, r/m (or r/m, reg depending on direction bit) */
        uint8_t reg = instr->modrm_reg;
        operand_size_t rm_size = op_size;

        /* Source size for MOVZX/MOVSX is the table's default_size (8 or 16) */
        if (instr->op == X86_OP_MOVZX || instr->op == X86_OP_MOVSX) {
            rm_size = effective->default_size;
        }

        if (instr->modrm_mod == 3) {
            /* Register-register */
            uint8_t rm = instr->modrm_rm;

            /* Direction bit: even opcodes = r/m,reg; odd = reg,r/m
             * For MOV 88/8A: 88 = r/m,r (store); 8A = r,r/m (load)
             * For MOV 89/8B: 89 = r/m,r (store); 8B = r,r/m (load)
             * For ALU: even = r/m,r; odd = r,r/m */
            bool store_direction = false;
            if (!is_2byte) {
                uint8_t op_low = primary_opcode & 0x07;
                if (op_low == 0 || op_low == 1) {
                    /* r/m, reg form */
                    store_direction = true;
                }
                /* 0x88, 0x89 are MOV store (r/m <- reg) */
                if (primary_opcode == 0x88 || primary_opcode == 0x89)
                    store_direction = true;
                if (primary_opcode == 0x8A || primary_opcode == 0x8B)
                    store_direction = false;
            }

            if (store_direction) {
                build_reg_operand(&instr->operands[0], rm, op_size);
                build_reg_operand(&instr->operands[1], reg, op_size);
            } else {
                build_reg_operand(&instr->operands[0], reg, op_size);
                build_reg_operand(&instr->operands[1], rm, rm_size);
            }
        } else {
            /* Register-memory */
            bool store_direction = false;
            if (!is_2byte) {
                uint8_t op_low = primary_opcode & 0x07;
                if (op_low == 0 || op_low == 1)
                    store_direction = true;
                if (primary_opcode == 0x88 || primary_opcode == 0x89)
                    store_direction = true;
                if (primary_opcode == 0x8A || primary_opcode == 0x8B)
                    store_direction = false;
            }

            if (store_direction) {
                decode_memory_operand(&instr->operands[0], instr, op_size);
                instr->operands[0].mem.disp = displacement;
                build_reg_operand(&instr->operands[1], reg, op_size);
            } else {
                build_reg_operand(&instr->operands[0], reg, op_size);
                decode_memory_operand(&instr->operands[1], instr, rm_size);
                instr->operands[1].mem.disp = displacement;
            }
        }
        instr->num_operands = 2;

        /* 3-operand IMUL r, r/m, imm */
        if (instr->op == X86_OP_IMUL && imm_bytes > 0 &&
            (primary_opcode == 0x69 || primary_opcode == 0x6B)) {
            build_imm_operand(&instr->operands[2], imm_value, op_size);
            instr->num_operands = 3;
        }
        break;
    }

    case ENC_GROUP:
    case ENC_MODRM_RM: {
        /* r/m operand (possibly + immediate) */
        if (instr->modrm_mod == 3) {
            build_reg_operand(&instr->operands[0], instr->modrm_rm, op_size);
        } else {
            decode_memory_operand(&instr->operands[0], instr, op_size);
            instr->operands[0].mem.disp = displacement;
        }
        instr->num_operands = 1;

        if (imm_bytes > 0) {
            operand_size_t imm_op_size = (imm_bytes == 1) ? SIZE_8 :
                                         (imm_bytes == 2) ? SIZE_16 :
                                         (imm_bytes == 4) ? SIZE_32 : SIZE_64;
            build_imm_operand(&instr->operands[1], imm_value, imm_op_size);
            instr->num_operands = 2;
        }

        /* Group 2 shift by 1 or CL: add second operand */
        if (group_num == 2) {
            if (primary_opcode == 0xD0 || primary_opcode == 0xD1) {
                /* Shift by 1 */
                build_imm_operand(&instr->operands[1], 1, SIZE_8);
                instr->num_operands = 2;
            } else if (primary_opcode == 0xD2 || primary_opcode == 0xD3) {
                /* Shift by CL */
                build_reg_operand(&instr->operands[1], X86_RCX, SIZE_8);
                instr->num_operands = 2;
            }
        }
        break;
    }

    case ENC_ACC_IMM: {
        /* AL/AX/EAX/RAX, imm */
        build_reg_operand(&instr->operands[0], X86_RAX, op_size);
        operand_size_t imm_op_size = (imm_bytes == 1) ? SIZE_8 :
                                     (imm_bytes == 2) ? SIZE_16 :
                                     (imm_bytes == 4) ? SIZE_32 : SIZE_64;
        build_imm_operand(&instr->operands[1], imm_value, imm_op_size);
        instr->num_operands = 2;
        break;
    }

    case ENC_REG_IMM: {
        /* Register in low 3 bits + REX.B, then immediate */
        uint8_t reg = (primary_opcode & 7) | (instr->rex_b ? 8 : 0);
        build_reg_operand(&instr->operands[0], reg, op_size);

        operand_size_t imm_op_size = (imm_bytes == 1) ? SIZE_8 :
                                     (imm_bytes == 2) ? SIZE_16 :
                                     (imm_bytes == 4) ? SIZE_32 : SIZE_64;
        build_imm_operand(&instr->operands[1], imm_value, imm_op_size);
        instr->num_operands = 2;
        break;
    }

    case ENC_REG_ONLY: {
        /* Register in low 3 bits + REX.B */
        uint8_t reg = (primary_opcode & 7) | (instr->rex_b ? 8 : 0);
        build_reg_operand(&instr->operands[0], reg, op_size);
        instr->num_operands = 1;

        /* XCHG rAX, reg (0x91-0x97) has implicit rAX as second operand */
        if (instr->op == X86_OP_XCHG) {
            build_reg_operand(&instr->operands[1], X86_RAX, op_size);
            instr->num_operands = 2;
        }
        break;
    }

    case ENC_REL8: {
        build_rel_operand(&instr->operands[0], imm_value);
        instr->num_operands = 1;
        break;
    }

    case ENC_REL32: {
        build_rel_operand(&instr->operands[0], imm_value);
        instr->num_operands = 1;
        break;
    }

    case ENC_FIXED: {
        /* Fixed/implicit encoding */
        if (imm_bytes > 0) {
            /* PUSH imm */
            operand_size_t imm_op_size = (imm_bytes == 1) ? SIZE_8 :
                                         (imm_bytes == 4) ? SIZE_32 : SIZE_64;
            build_imm_operand(&instr->operands[0], imm_value, imm_op_size);
            instr->num_operands = 1;
        } else {
            instr->num_operands = 0;
        }
        break;
    }

    default:
        break;
    }

    return (int)instr->length;
}

const char *x86_cc_name(x86_cc_t cc)
{
    if (cc > 0xF)
        return "??";
    return cc_names[cc];
}

const char *x86_format_instr(const x86_instr_t *instr)
{
    static char buf[256];
    char *p = buf;
    char *end = buf + sizeof(buf) - 1;
    int n;

    if (instr->op == X86_OP_INVALID) {
        snprintf(buf, sizeof(buf), "(invalid)");
        return buf;
    }

    /* Print address */
    n = snprintf(p, end - p, "%016llx  ", (unsigned long long)instr->addr);
    p += n;

    /* Print lock prefix */
    if (instr->has_lock) {
        n = snprintf(p, end - p, "lock ");
        p += n;
    }
    /* Print rep/repne prefix */
    if (instr->has_rep) {
        n = snprintf(p, end - p, "rep ");
        p += n;
    }
    if (instr->has_repne) {
        n = snprintf(p, end - p, "repne ");
        p += n;
    }

    /* Mnemonic */
    const char *mnem = NULL;

    switch (instr->op) {
    case X86_OP_JCC:
        n = snprintf(p, end - p, "j%s", x86_cc_name(instr->cc));
        p += n;
        break;
    case X86_OP_SETCC:
        n = snprintf(p, end - p, "set%s", x86_cc_name(instr->cc));
        p += n;
        break;
    case X86_OP_CMOVCC:
        n = snprintf(p, end - p, "cmov%s", x86_cc_name(instr->cc));
        p += n;
        break;
    case X86_OP_CDQE:  mnem = "cdqe"; break;
    case X86_OP_CBW:   mnem = "cbw"; break;
    case X86_OP_CWDE:  mnem = "cwde"; break;
    case X86_OP_CQO:   mnem = "cqo"; break;
    case X86_OP_CDQ:   mnem = "cdq"; break;
    case X86_OP_MOVSS: mnem = "movss"; break;
    case X86_OP_MOVSD: mnem = "movsd"; break;
    case X86_OP_ADDSS: mnem = "addss"; break;
    case X86_OP_ADDSD: mnem = "addsd"; break;
    case X86_OP_SUBSS: mnem = "subss"; break;
    case X86_OP_SUBSD: mnem = "subsd"; break;
    case X86_OP_MULSS: mnem = "mulss"; break;
    case X86_OP_MULSD: mnem = "mulsd"; break;
    case X86_OP_DIVSS: mnem = "divss"; break;
    case X86_OP_DIVSD: mnem = "divsd"; break;
    case X86_OP_SQRTSS: mnem = "sqrtss"; break;
    case X86_OP_SQRTSD: mnem = "sqrtsd"; break;
    case X86_OP_UCOMISD: mnem = "ucomisd"; break;
    case X86_OP_XORPD: mnem = "xorpd"; break;
    default: {
        /* Look up from tables based on instruction bytes */
        uint8_t b0 = instr->bytes[0];
        /* Skip prefixes to find opcode */
        size_t idx = 0;
        while (idx < instr->length) {
            uint8_t b = instr->bytes[idx];
            if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                b == 0x26 || b == 0x2E || b == 0x36 || b == 0x3E ||
                b == 0x64 || b == 0x65 ||
                (b >= 0x40 && b <= 0x4F)) {
                idx++;
                continue;
            }
            break;
        }
        if (idx < instr->length) {
            b0 = instr->bytes[idx];
            if (b0 == 0x0F && idx + 1 < instr->length) {
                const opcode_entry_t *e2 = x86_lookup_2byte(instr->bytes[idx + 1]);
                mnem = e2->mnemonic;
            } else {
                const opcode_entry_t *e1 = x86_lookup_1byte(b0);
                if (e1->encoding == ENC_GROUP && instr->has_modrm) {
                    int gn = get_group_number(b0, false);
                    const opcode_entry_t *ge = x86_lookup_group(gn, (instr->modrm >> 3) & 7);
                    if (ge) mnem = ge->mnemonic;
                } else {
                    mnem = e1->mnemonic;
                }
            }
        }
        break;
    }
    }

    if (mnem) {
        n = snprintf(p, end - p, "%s", mnem);
        p += n;
    }

    /* Operands */
    for (int i = 0; i < instr->num_operands; i++) {
        if (i == 0)
            *p++ = ' ';
        else {
            *p++ = ',';
            *p++ = ' ';
        }

        const x86_operand_t *op = &instr->operands[i];
        switch (op->type) {
        case OPERAND_REG:
            n = snprintf(p, end - p, "%s",
                         reg_name(op->reg.reg, op->size, instr->has_rex));
            p += n;
            break;

        case OPERAND_IMM:
            if (op->imm.value < 0)
                n = snprintf(p, end - p, "-0x%llx",
                             (unsigned long long)(-op->imm.value));
            else
                n = snprintf(p, end - p, "0x%llx",
                             (unsigned long long)op->imm.value);
            p += n;
            break;

        case OPERAND_MEM: {
            /* Size prefix */
            switch (op->size) {
            case SIZE_8:  n = snprintf(p, end - p, "byte ptr "); p += n; break;
            case SIZE_16: n = snprintf(p, end - p, "word ptr "); p += n; break;
            case SIZE_32: n = snprintf(p, end - p, "dword ptr "); p += n; break;
            case SIZE_64: n = snprintf(p, end - p, "qword ptr "); p += n; break;
            }

            *p++ = '[';
            bool need_plus = false;

            if (op->mem.rip_rel) {
                n = snprintf(p, end - p, "rip");
                p += n;
                need_plus = true;
            } else if (op->mem.base >= 0) {
                n = snprintf(p, end - p, "%s", reg_names_64[op->mem.base & 0xF]);
                p += n;
                need_plus = true;
            }

            if (op->mem.index >= 0) {
                if (need_plus) *p++ = '+';
                n = snprintf(p, end - p, "%s", reg_names_64[op->mem.index & 0xF]);
                p += n;
                if (op->mem.scale > 1) {
                    n = snprintf(p, end - p, "*%d", op->mem.scale);
                    p += n;
                }
                need_plus = true;
            }

            if (op->mem.disp != 0 || !need_plus) {
                if (need_plus) {
                    if (op->mem.disp >= 0)
                        n = snprintf(p, end - p, "+0x%llx",
                                     (unsigned long long)op->mem.disp);
                    else
                        n = snprintf(p, end - p, "-0x%llx",
                                     (unsigned long long)(-op->mem.disp));
                } else {
                    n = snprintf(p, end - p, "0x%llx",
                                 (unsigned long long)op->mem.disp);
                }
                p += n;
            }

            *p++ = ']';
            break;
        }

        case OPERAND_REL: {
            /* Show target address = addr + length + offset */
            uint64_t target = instr->addr + instr->length + op->rel.offset;
            n = snprintf(p, end - p, "0x%llx", (unsigned long long)target);
            p += n;
            break;
        }

        case OPERAND_NONE:
            break;
        }
    }

    *p = '\0';
    return buf;
}

bool x86_is_block_terminator(const x86_instr_t *instr)
{
    switch (instr->op) {
    case X86_OP_JMP:
    case X86_OP_JCC:
    case X86_OP_CALL:
    case X86_OP_RET:
    case X86_OP_SYSCALL:
        return true;
    default:
        return false;
    }
}

bool x86_reads_flags(const x86_instr_t *instr)
{
    switch (instr->op) {
    /* Conditional branches/sets/moves read flags */
    case X86_OP_JCC:
    case X86_OP_SETCC:
    case X86_OP_CMOVCC:
    /* ADC/SBB read carry flag */
    case X86_OP_ADC:
    case X86_OP_SBB:
    /* Rotate through carry */
    case X86_OP_RCL:
    case X86_OP_RCR:
        return true;
    default:
        return false;
    }
}

bool x86_writes_flags(const x86_instr_t *instr)
{
    switch (instr->op) {
    /* Arithmetic operations write flags */
    case X86_OP_ADD:
    case X86_OP_SUB:
    case X86_OP_ADC:
    case X86_OP_SBB:
    case X86_OP_INC:
    case X86_OP_DEC:
    case X86_OP_NEG:
    case X86_OP_MUL:
    case X86_OP_IMUL:
    case X86_OP_DIV:
    case X86_OP_IDIV:
    /* Logic operations */
    case X86_OP_AND:
    case X86_OP_OR:
    case X86_OP_XOR:
    case X86_OP_TEST:
    case X86_OP_NOT:
    /* Compare */
    case X86_OP_CMP:
    /* Shifts */
    case X86_OP_SHL:
    case X86_OP_SHR:
    case X86_OP_SAR:
    case X86_OP_ROL:
    case X86_OP_ROR:
    case X86_OP_RCL:
    case X86_OP_RCR:
    /* SSE compare */
    case X86_OP_UCOMISS:
    case X86_OP_UCOMISD:
        return true;
    default:
        return false;
    }
}
