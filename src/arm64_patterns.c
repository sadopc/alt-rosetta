/*
 * arm64_patterns.c - x86_64 → ARM64 translation patterns
 *
 * Each pattern function translates a specific x86 instruction (or family)
 * into one or more ARM64 instructions. These are called from translate.c
 * during direct translation (Phase 4-5, before IR is enabled).
 */

#include "alt_rosetta.h"
#include "arm64_emit.h"
#include "x86_decode.h"
#include "translate.h"
#include "flags.h"
#include "syscall.h"
#include "debug.h"

/* Helper: get ARM64 register for an x86 register operand */
static uint32_t arm_reg(const x86_operand_t *op) {
    return x86_to_arm_reg(op->reg.reg);
}

/* Helper: determine if we should use 64-bit (sf=1) based on operand size */
static bool is_64bit(const x86_instr_t *instr) {
    return instr->op_size == SIZE_64;
}

/* Helper: emit code to load a memory operand's effective address into a scratch reg.
 * Returns the scratch register number (ARM_SCRATCH0).
 *
 * For RIP-relative addressing:
 *   - LEA: produces the guest virtual address (caller stores it in a guest register)
 *   - Load/Store: produces the host address so the JIT code can access the data
 *
 * The 'ctx' parameter is needed to resolve guest→host for RIP-relative memory ops.
 * Pass NULL for LEA (guest address mode). */
static uint32_t emit_lea_to_scratch(jit_memory_t *jit, const x86_instr_t *instr,
                                     const x86_operand_t *mem,
                                     const translator_ctx_t *ctx) {
    uint32_t scratch = ARM_SCRATCH0;

    if (mem->mem.rip_rel) {
        /* RIP-relative: addr = next_instruction_addr + displacement */
        uint64_t guest_addr = instr->addr + instr->length + mem->mem.disp;
        if (ctx) {
            /* Resolve to host address for direct memory access */
            uint8_t *host = macho_guest_to_host(&ctx->binary, guest_addr);
            if (host) {
                emit_mov_imm64(jit, scratch, (uint64_t)(uintptr_t)host);
            } else {
                /* Fallback: try JIT guest regions (stack, etc.) */
                host = jit_guest_to_host(&ctx->jit, guest_addr);
                if (host) {
                    emit_mov_imm64(jit, scratch, (uint64_t)(uintptr_t)host);
                } else {
                    /* Can't resolve - use guest addr (will likely fault) */
                    emit_mov_imm64(jit, scratch, guest_addr);
                }
            }
        } else {
            /* LEA mode: produce guest virtual address */
            emit_mov_imm64(jit, scratch, guest_addr);
        }
    } else if (mem->mem.base >= 0 && mem->mem.index >= 0) {
        /* [base + index*scale + disp] */
        uint32_t base_arm = x86_to_arm_reg(mem->mem.base);
        uint32_t idx_arm = x86_to_arm_reg(mem->mem.index);

        if (mem->mem.scale == 1 && mem->mem.disp == 0) {
            emit_add_reg(jit, true, scratch, base_arm, idx_arm);
        } else {
            /* Scale the index */
            if (mem->mem.scale > 1) {
                uint32_t shift = 0;
                switch (mem->mem.scale) {
                    case 2: shift = 1; break;
                    case 4: shift = 2; break;
                    case 8: shift = 3; break;
                }
                emit_add_reg_shifted(jit, true, scratch, base_arm, idx_arm,
                                     ARM_SHIFT_LSL, shift);
            } else {
                emit_add_reg(jit, true, scratch, base_arm, idx_arm);
            }
            /* Add displacement */
            if (mem->mem.disp != 0) {
                if (mem->mem.disp > 0 && mem->mem.disp < 4096) {
                    emit_add_imm(jit, true, scratch, scratch, (uint32_t)mem->mem.disp);
                } else if (mem->mem.disp < 0 && mem->mem.disp > -4096) {
                    emit_sub_imm(jit, true, scratch, scratch, (uint32_t)(-mem->mem.disp));
                } else {
                    emit_mov_imm64(jit, ARM_SCRATCH1, (uint64_t)(int64_t)mem->mem.disp);
                    emit_add_reg(jit, true, scratch, scratch, ARM_SCRATCH1);
                }
            }
        }
    } else if (mem->mem.base >= 0) {
        /* [base + disp] */
        uint32_t base_arm = x86_to_arm_reg(mem->mem.base);
        if (mem->mem.disp == 0) {
            emit_mov_reg(jit, true, scratch, base_arm);
        } else if (mem->mem.disp > 0 && mem->mem.disp < 4096) {
            emit_add_imm(jit, true, scratch, base_arm, (uint32_t)mem->mem.disp);
        } else if (mem->mem.disp < 0 && mem->mem.disp > -4096) {
            emit_sub_imm(jit, true, scratch, base_arm, (uint32_t)(-mem->mem.disp));
        } else {
            emit_mov_imm64(jit, scratch, (uint64_t)(int64_t)mem->mem.disp);
            emit_add_reg(jit, true, scratch, scratch, base_arm);
        }
    } else {
        /* [disp] - absolute address */
        emit_mov_imm64(jit, scratch, (uint64_t)(int64_t)mem->mem.disp);
    }

    return scratch;
}

/* Helper: emit a load from guest memory into a register */
static void emit_guest_load(jit_memory_t *jit, uint32_t dst, uint32_t addr_reg,
                            operand_size_t size) {
    switch (size) {
        case SIZE_8:  emit_ldrb_imm(jit, dst, addr_reg, 0); break;
        case SIZE_16: emit_ldrh_imm(jit, dst, addr_reg, 0); break;
        case SIZE_32: emit_ldr_imm(jit, false, dst, addr_reg, 0); break;
        case SIZE_64: emit_ldr_imm(jit, true, dst, addr_reg, 0); break;
    }
}

/* Helper: emit a store to guest memory from a register */
static void emit_guest_store(jit_memory_t *jit, uint32_t src, uint32_t addr_reg,
                             operand_size_t size) {
    switch (size) {
        case SIZE_8:  emit_strb_imm(jit, src, addr_reg, 0); break;
        case SIZE_16: emit_strh_imm(jit, src, addr_reg, 0); break;
        case SIZE_32: emit_str_imm(jit, false, src, addr_reg, 0); break;
        case SIZE_64: emit_str_imm(jit, true, src, addr_reg, 0); break;
    }
}

/* Helper: mask a register to the appropriate operand size (zero-extend) */
static void emit_mask_to_size(jit_memory_t *jit, uint32_t reg, operand_size_t size) {
    switch (size) {
        case SIZE_8:
            emit_uxtb(jit, reg, reg);
            break;
        case SIZE_16:
            emit_uxth(jit, reg, reg);
            break;
        case SIZE_32:
            /* Writing a 32-bit register in ARM64 automatically zeros upper 32 bits */
            emit_mov_reg(jit, false, reg, reg);
            break;
        case SIZE_64:
            /* Nothing needed */
            break;
    }
}

/* ---- Translation Pattern Functions ---- */

/* NOP - no operation */
int pattern_nop(translator_ctx_t *ctx, const x86_instr_t *instr) {
    (void)instr;
    emit_nop(&ctx->jit);
    return 0;
}

/* MOV reg, imm */
int pattern_mov_reg_imm(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    int64_t imm = instr->operands[1].imm.value;

    if (instr->op_size == SIZE_64) {
        emit_mov_imm64(&ctx->jit, dst, (uint64_t)imm);
    } else {
        emit_mov_imm32(&ctx->jit, dst, (uint32_t)(uint64_t)imm);
    }
    return 0;
}

/* MOV reg, reg */
int pattern_mov_reg_reg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    uint32_t src = arm_reg(&instr->operands[1]);
    bool sf = is_64bit(instr);

    emit_mov_reg(&ctx->jit, sf, dst, src);
    if (!sf) {
        /* 32-bit mov zero-extends to 64 bits on x86_64 */
        /* ARM64's 32-bit MOV (using W registers) already zeros upper 32 */
    }
    return 0;
}

/* MOV reg, [mem] */
int pattern_mov_reg_mem(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
    emit_guest_load(&ctx->jit, dst, addr, instr->op_size);
    return 0;
}

/* MOV [mem], reg */
int pattern_mov_mem_reg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t src = arm_reg(&instr->operands[1]);
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
    emit_guest_store(&ctx->jit, src, addr, instr->op_size);
    return 0;
}

/* MOV [mem], imm */
int pattern_mov_mem_imm(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
    emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)instr->operands[1].imm.value);
    emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
    return 0;
}

/* LEA reg, [mem] - load effective address (no memory access) */
int pattern_lea(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], NULL);
    if (addr != dst) {
        emit_mov_reg(&ctx->jit, is_64bit(instr), dst, addr);
    }
    return 0;
}

/* PUSH reg/imm - push to guest stack */
int pattern_push(translator_ctx_t *ctx, const x86_instr_t *instr) {
    /* RSP -= 8; [RSP] = operand */
    emit_sub_imm(&ctx->jit, true, ARM_RSP, ARM_RSP, 8);

    if (instr->operands[0].type == OPERAND_REG) {
        uint32_t src = arm_reg(&instr->operands[0]);
        emit_str_imm(&ctx->jit, true, src, ARM_RSP, 0);
    } else if (instr->operands[0].type == OPERAND_IMM) {
        emit_mov_imm64(&ctx->jit, ARM_SCRATCH0, (uint64_t)instr->operands[0].imm.value);
        emit_str_imm(&ctx->jit, true, ARM_SCRATCH0, ARM_RSP, 0);
    }
    return 0;
}

/* POP reg - pop from guest stack */
int pattern_pop(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    /* operand = [RSP]; RSP += 8 */
    emit_ldr_imm(&ctx->jit, true, dst, ARM_RSP, 0);
    emit_add_imm(&ctx->jit, true, ARM_RSP, ARM_RSP, 8);
    return 0;
}

/* ADD/SUB/AND/OR/XOR/CMP/TEST reg, reg */
int pattern_alu_reg_reg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    uint32_t src = arm_reg(&instr->operands[1]);
    bool sf = is_64bit(instr);

    switch (instr->op) {
        case X86_OP_ADD:
            emit_add_reg(&ctx->jit, sf, dst, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_ADD, dst, src, dst, instr->op_size);
            break;
        case X86_OP_SUB:
            emit_sub_reg(&ctx->jit, sf, dst, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, src, dst, instr->op_size);
            break;
        case X86_OP_AND:
            emit_and_reg(&ctx->jit, sf, dst, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, src, dst, instr->op_size);
            break;
        case X86_OP_OR:
            emit_orr_reg(&ctx->jit, sf, dst, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_OR, dst, src, dst, instr->op_size);
            break;
        case X86_OP_XOR:
            emit_eor_reg(&ctx->jit, sf, dst, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_XOR, dst, src, dst, instr->op_size);
            break;
        case X86_OP_CMP:
            /* CMP = SUB but discard result */
            emit_subs_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, src, ARM_SCRATCH0, instr->op_size);
            break;
        case X86_OP_TEST:
            /* TEST = AND but discard result */
            emit_ands_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, src, ARM_SCRATCH0, instr->op_size);
            break;
        default:
            return -1;
    }
    return 0;
}

/* ADD/SUB/AND/OR/XOR/CMP reg, imm */
int pattern_alu_reg_imm(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    int64_t imm = instr->operands[1].imm.value;
    bool sf = is_64bit(instr);

    /* For small immediates, use immediate forms. For large ones, load to scratch. */
    bool use_imm = (imm >= 0 && imm < 4096);
    uint32_t src_reg = ARM_SCRATCH1;

    if (!use_imm) {
        emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
    }

    switch (instr->op) {
        case X86_OP_ADD:
            if (use_imm) emit_add_imm(&ctx->jit, sf, dst, dst, (uint32_t)imm);
            else emit_add_reg(&ctx->jit, sf, dst, dst, src_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_ADD, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_SUB:
            if (use_imm) emit_sub_imm(&ctx->jit, sf, dst, dst, (uint32_t)imm);
            else emit_sub_reg(&ctx->jit, sf, dst, dst, src_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_AND:
            if (!use_imm) {
                /* AND doesn't have an immediate form in ARM64 (needs bitmask encoding) */
            }
            emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
            emit_and_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_OR:
            emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
            emit_orr_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_OR, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_XOR:
            emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
            emit_eor_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_XOR, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_CMP:
            emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
            emit_subs_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, ARM_SCRATCH1, ARM_SCRATCH0, instr->op_size);
            break;
        case X86_OP_TEST:
            emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, (uint64_t)imm);
            emit_ands_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, ARM_SCRATCH1, ARM_SCRATCH0, instr->op_size);
            break;
        default:
            return -1;
    }
    return 0;
}

/* ALU reg, [mem] */
int pattern_alu_reg_mem(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
    bool sf = is_64bit(instr);

    /* Load memory operand into scratch */
    emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);

    switch (instr->op) {
        case X86_OP_ADD:
            emit_add_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_ADD, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_SUB:
            emit_sub_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_AND:
            emit_and_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_OR:
            emit_orr_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_OR, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_XOR:
            emit_eor_reg(&ctx->jit, sf, dst, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_XOR, dst, ARM_SCRATCH1, dst, instr->op_size);
            break;
        case X86_OP_CMP:
            emit_subs_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, dst, ARM_SCRATCH1, ARM_SCRATCH0, instr->op_size);
            break;
        case X86_OP_TEST:
            emit_ands_reg(&ctx->jit, sf, ARM_SCRATCH0, dst, ARM_SCRATCH1);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, dst, ARM_SCRATCH1, ARM_SCRATCH0, instr->op_size);
            break;
        default:
            return -1;
    }
    return 0;
}

/* ALU [mem], imm (CMP/TEST/ADD/SUB/AND/OR/XOR with memory destination and immediate) */
int pattern_alu_mem_imm(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
    bool sf = is_64bit(instr);
    int64_t imm = instr->operands[1].imm.value;

    /* Load memory operand into SCRATCH1 */
    emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);

    /* Load immediate into a temp (reuse SCRATCH0 carefully - addr is already consumed) */
    uint32_t imm_reg = ARM_SCRATCH0;
    emit_mov_imm64(&ctx->jit, imm_reg, (uint64_t)imm);

    switch (instr->op) {
        case X86_OP_CMP:
            /* Use TMP0 for result so imm_reg (SCRATCH0) is preserved for lazy flags */
            emit_subs_reg(&ctx->jit, sf, ARM_TMP0, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, ARM_SCRATCH1, imm_reg, ARM_TMP0, instr->op_size);
            break;
        case X86_OP_TEST:
            emit_ands_reg(&ctx->jit, sf, ARM_TMP0, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, ARM_SCRATCH1, imm_reg, ARM_TMP0, instr->op_size);
            break;
        case X86_OP_ADD:
            emit_add_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_ADD, ARM_SCRATCH1, imm_reg, ARM_SCRATCH1, instr->op_size);
            /* Store result back */
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        case X86_OP_SUB:
            emit_sub_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, ARM_SCRATCH1, imm_reg, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        case X86_OP_AND:
            emit_and_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, ARM_SCRATCH1, imm_reg, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        case X86_OP_OR:
            emit_orr_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_OR, ARM_SCRATCH1, imm_reg, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        case X86_OP_XOR:
            emit_eor_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, imm_reg);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_XOR, ARM_SCRATCH1, imm_reg, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        default:
            return -1;
    }
    return 0;
}

/* ALU [mem], reg */
int pattern_alu_mem_reg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
    uint32_t src = arm_reg(&instr->operands[1]);
    bool sf = is_64bit(instr);

    /* Load memory operand into SCRATCH1 */
    emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);

    switch (instr->op) {
        case X86_OP_CMP:
            emit_subs_reg(&ctx->jit, sf, ARM_SCRATCH0, ARM_SCRATCH1, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, ARM_SCRATCH1, src, ARM_SCRATCH0, instr->op_size);
            break;
        case X86_OP_TEST:
            emit_ands_reg(&ctx->jit, sf, ARM_SCRATCH0, ARM_SCRATCH1, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_AND, ARM_SCRATCH1, src, ARM_SCRATCH0, instr->op_size);
            break;
        case X86_OP_ADD:
            emit_add_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_ADD, ARM_SCRATCH1, src, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        case X86_OP_SUB:
            emit_sub_reg(&ctx->jit, sf, ARM_SCRATCH1, ARM_SCRATCH1, src);
            emit_set_lazy_flags(&ctx->jit, FLAGS_OP_SUB, ARM_SCRATCH1, src, ARM_SCRATCH1, instr->op_size);
            addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
            emit_guest_store(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
            break;
        default:
            return -1;
    }
    return 0;
}

/* INC reg */
int pattern_inc(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);
    /* Save original for lazy flags */
    emit_mov_reg(&ctx->jit, sf, ARM_SCRATCH0, dst);
    emit_add_imm(&ctx->jit, sf, dst, dst, 1);
    emit_set_lazy_flags(&ctx->jit, FLAGS_OP_INC, ARM_SCRATCH0, ARM_SCRATCH0, dst, instr->op_size);
    return 0;
}

/* DEC reg */
int pattern_dec(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);
    emit_mov_reg(&ctx->jit, sf, ARM_SCRATCH0, dst);
    emit_sub_imm(&ctx->jit, sf, dst, dst, 1);
    emit_set_lazy_flags(&ctx->jit, FLAGS_OP_DEC, ARM_SCRATCH0, ARM_SCRATCH0, dst, instr->op_size);
    return 0;
}

/* NEG reg */
int pattern_neg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);
    emit_mov_reg(&ctx->jit, sf, ARM_SCRATCH0, dst);
    /* NEG = SUB from zero */
    emit_sub_reg(&ctx->jit, sf, dst, ARM_SP, dst);  /* XZR encoded as SP in some contexts */
    /* Actually: use 0 - reg. ARM64: SUB Rd, XZR, Rm → need special encoding.
     * Use: MOV scratch, #0; SUB dst, scratch, dst */
    emit_movz(&ctx->jit, sf, ARM_SCRATCH1, 0, 0);
    emit_sub_reg(&ctx->jit, sf, dst, ARM_SCRATCH1, dst);
    emit_set_lazy_flags(&ctx->jit, FLAGS_OP_NEG, ARM_SCRATCH0, ARM_SCRATCH0, dst, instr->op_size);
    return 0;
}

/* NOT reg */
int pattern_not(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);
    /* NOT = ORN Rd, XZR, Rm (bitwise NOT) */
    emit_orn_reg(&ctx->jit, sf, dst, 31, dst);  /* XZR = reg 31 */
    /* NOT does not affect flags */
    return 0;
}

/* SHL/SHR/SAR reg, imm8 or CL */
int pattern_shift(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);

    if (instr->operands[1].type == OPERAND_IMM) {
        uint32_t amount = (uint32_t)instr->operands[1].imm.value;
        uint32_t width = sf ? 64 : 32;

        switch (instr->op) {
            case X86_OP_SHL:
                /* LSL via UBFM: UBFM Rd, Rn, #(-amount mod width), #(width-1-amount) */
                emit_ubfm(&ctx->jit, sf, dst, dst, (-amount) % width, width - 1 - amount);
                break;
            case X86_OP_SHR:
                /* LSR via UBFM: UBFM Rd, Rn, #amount, #(width-1) */
                emit_ubfm(&ctx->jit, sf, dst, dst, amount, width - 1);
                break;
            case X86_OP_SAR:
                /* ASR via SBFM: SBFM Rd, Rn, #amount, #(width-1) */
                emit_sbfm(&ctx->jit, sf, dst, dst, amount, width - 1);
                break;
            default:
                return -1;
        }
    } else {
        /* Shift by CL (RCX → X1) */
        uint32_t cl = x86_to_arm_reg(X86_RCX);
        switch (instr->op) {
            case X86_OP_SHL: emit_lslv(&ctx->jit, sf, dst, dst, cl); break;
            case X86_OP_SHR: emit_lsrv(&ctx->jit, sf, dst, dst, cl); break;
            case X86_OP_SAR: emit_asrv(&ctx->jit, sf, dst, dst, cl); break;
            default: return -1;
        }
    }

    emit_set_lazy_flags(&ctx->jit,
        instr->op == X86_OP_SHL ? FLAGS_OP_SHL :
        instr->op == X86_OP_SHR ? FLAGS_OP_SHR : FLAGS_OP_SAR,
        dst, ARM_SCRATCH0, dst, instr->op_size);
    return 0;
}

/* IMUL reg, reg/mem (two-operand form) */
int pattern_imul(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);

    uint32_t src;
    if (instr->operands[1].type == OPERAND_REG) {
        src = arm_reg(&instr->operands[1]);
    } else if (instr->operands[1].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
        emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
        src = ARM_SCRATCH1;
    } else {
        return -1;
    }

    emit_mul(&ctx->jit, sf, dst, dst, src);
    emit_set_lazy_flags(&ctx->jit, FLAGS_OP_IMUL, dst, src, dst, instr->op_size);
    return 0;
}

/* MOVZX reg, reg/mem (zero-extend) */
int pattern_movzx(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    operand_size_t src_size = instr->operands[1].size;

    if (instr->operands[1].type == OPERAND_REG) {
        uint32_t src = arm_reg(&instr->operands[1]);
        if (src != dst) emit_mov_reg(&ctx->jit, true, dst, src);
    } else if (instr->operands[1].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
        emit_guest_load(&ctx->jit, dst, addr, src_size);
        /* Load already zero-extends for LDRB/LDRH */
        return 0;
    } else {
        return -1;
    }

    /* Zero-extend to full register */
    emit_mask_to_size(&ctx->jit, dst, src_size);
    return 0;
}

/* MOVSX/MOVSXD reg, reg/mem (sign-extend) */
int pattern_movsx(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    operand_size_t src_size = instr->operands[1].size;
    bool sf = is_64bit(instr);

    if (instr->operands[1].type == OPERAND_REG) {
        uint32_t src = arm_reg(&instr->operands[1]);
        if (src != dst) emit_mov_reg(&ctx->jit, true, dst, src);
    } else if (instr->operands[1].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
        /* Use sign-extending loads */
        switch (src_size) {
            case SIZE_8:  emit_ldrsb(&ctx->jit, sf, dst, addr, 0); return 0;
            case SIZE_16: emit_ldrsh(&ctx->jit, sf, dst, addr, 0); return 0;
            case SIZE_32: emit_ldrsw_imm(&ctx->jit, dst, addr, 0); return 0;
            default: return -1;
        }
    } else {
        return -1;
    }

    /* Sign-extend register */
    switch (src_size) {
        case SIZE_8:  emit_sxtb(&ctx->jit, sf, dst, dst); break;
        case SIZE_16: emit_sxth(&ctx->jit, sf, dst, dst); break;
        case SIZE_32: emit_sxtw(&ctx->jit, dst, dst); break;
        default: break;
    }
    return 0;
}

/* CDQ/CQO - sign-extend RAX into RDX:RAX */
int pattern_cdq_cqo(translator_ctx_t *ctx, const x86_instr_t *instr) {
    bool sf = is_64bit(instr);
    /* RDX = (RAX < 0) ? -1 : 0 */
    /* ASR by 31 (or 63) to replicate sign bit */
    if (sf) {
        /* CQO: sign-extend RAX → RDX:RAX */
        emit_sbfm(&ctx->jit, true, ARM_RDX, ARM_RAX, 63, 63);  /* ASR by 63 */
    } else {
        /* CDQ: sign-extend EAX → EDX:EAX */
        emit_sbfm(&ctx->jit, false, ARM_RDX, ARM_RAX, 31, 31);  /* ASR by 31 */
    }
    return 0;
}

/* CDQE: sign-extend EAX (32-bit) → RAX (64-bit)
 * Also handles CBW (AL→AX) and CWDE (AX→EAX) */
int pattern_cdqe(translator_ctx_t *ctx, const x86_instr_t *instr) {
    (void)instr;
    /* SXTW X0, W0 = SBFM X0, X0, #0, #31 */
    emit_sbfm(&ctx->jit, true, ARM_RAX, ARM_RAX, 0, 31);
    return 0;
}

/* XCHG reg, reg */
int pattern_xchg(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t r1 = arm_reg(&instr->operands[0]);
    uint32_t r2 = arm_reg(&instr->operands[1]);
    bool sf = is_64bit(instr);

    emit_mov_reg(&ctx->jit, sf, ARM_SCRATCH0, r1);
    emit_mov_reg(&ctx->jit, sf, r1, r2);
    emit_mov_reg(&ctx->jit, sf, r2, ARM_SCRATCH0);
    return 0;
}

/* JMP rel (direct jump) */
int pattern_jmp_direct(translator_ctx_t *ctx, const x86_instr_t *instr) {
    /* Target = instr->addr + instr->length + offset */
    int64_t offset = instr->operands[0].rel.offset;
    uint64_t target = instr->addr + instr->length + offset;

    /* Store target address in RIP register */
    emit_mov_imm64(&ctx->jit, ARM_RIP, target);
    /* Return to translator dispatch loop */
    emit_ret(&ctx->jit, ARM_LR);
    return 0;
}

/* JMP reg/[mem] (indirect jump) */
int pattern_jmp_indirect(translator_ctx_t *ctx, const x86_instr_t *instr) {
    if (instr->operands[0].type == OPERAND_REG) {
        uint32_t src = arm_reg(&instr->operands[0]);
        emit_mov_reg(&ctx->jit, true, ARM_RIP, src);
    } else if (instr->operands[0].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
        emit_ldr_imm(&ctx->jit, true, ARM_RIP, addr, 0);
    }
    emit_ret(&ctx->jit, ARM_LR);
    return 0;
}

/* Jcc rel (conditional jump) */
int pattern_jcc(translator_ctx_t *ctx, const x86_instr_t *instr) {
    int64_t offset = instr->operands[0].rel.offset;
    uint64_t target = instr->addr + instr->length + offset;
    uint64_t fallthrough = instr->addr + instr->length;

    /* Compute flags from lazy state */
    emit_compute_flags(&ctx->jit, instr->cc);

    /* Map x86 CC to ARM64 CC */
    arm64_cc_t arm_cc = x86_cc_to_arm64(instr->cc);

    /* B.cond to taken path */
    /* We emit: B.cond +2 (skip fallthrough), then fallthrough code, then taken code */
    /* Actually: emit B.cond to a forward label, load fallthrough RIP, RET.
     * If condition true: load target RIP, RET. */

    /* Emit: B.cond .taken */
    uint32_t *branch_loc = jit_cursor(&ctx->jit);
    emit_bcond(&ctx->jit, arm_cc, 0);  /* Placeholder offset */

    /* Fallthrough path: set RIP = fallthrough, return to dispatcher */
    emit_mov_imm64(&ctx->jit, ARM_RIP, fallthrough);
    emit_ret(&ctx->jit, ARM_LR);

    /* Taken path - patch the branch to here */
    uint32_t *taken_loc = jit_cursor(&ctx->jit);
    emit_patch_bcond(branch_loc, taken_loc);

    emit_mov_imm64(&ctx->jit, ARM_RIP, target);
    emit_ret(&ctx->jit, ARM_LR);

    return 0;
}

/* CALL rel32 */
int pattern_call_direct(translator_ctx_t *ctx, const x86_instr_t *instr) {
    int64_t offset = instr->operands[0].rel.offset;
    uint64_t target = instr->addr + instr->length + offset;
    uint64_t return_addr = instr->addr + instr->length;

    /* Push return address onto guest stack */
    emit_sub_imm(&ctx->jit, true, ARM_RSP, ARM_RSP, 8);
    emit_mov_imm64(&ctx->jit, ARM_SCRATCH0, return_addr);
    emit_str_imm(&ctx->jit, true, ARM_SCRATCH0, ARM_RSP, 0);

    /* Set RIP to target */
    emit_mov_imm64(&ctx->jit, ARM_RIP, target);
    emit_ret(&ctx->jit, ARM_LR);
    return 0;
}

/* CALL reg/[mem] */
int pattern_call_indirect(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint64_t return_addr = instr->addr + instr->length;

    /* Get target address */
    if (instr->operands[0].type == OPERAND_REG) {
        uint32_t src = arm_reg(&instr->operands[0]);
        emit_mov_reg(&ctx->jit, true, ARM_SCRATCH0, src);
    } else if (instr->operands[0].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
        emit_ldr_imm(&ctx->jit, true, ARM_SCRATCH0, addr, 0);
    }

    /* Push return address */
    emit_sub_imm(&ctx->jit, true, ARM_RSP, ARM_RSP, 8);
    emit_mov_imm64(&ctx->jit, ARM_SCRATCH1, return_addr);
    emit_str_imm(&ctx->jit, true, ARM_SCRATCH1, ARM_RSP, 0);

    /* Set RIP to target */
    emit_mov_reg(&ctx->jit, true, ARM_RIP, ARM_SCRATCH0);
    emit_ret(&ctx->jit, ARM_LR);
    return 0;
}

/* RET */
int pattern_ret(translator_ctx_t *ctx, const x86_instr_t *instr) {
    (void)instr;
    /* Pop return address from guest stack into RIP */
    emit_ldr_imm(&ctx->jit, true, ARM_RIP, ARM_RSP, 0);
    emit_add_imm(&ctx->jit, true, ARM_RSP, ARM_RSP, 8);
    emit_ret(&ctx->jit, ARM_LR);
    return 0;
}

/* SETcc reg */
int pattern_setcc(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);

    emit_compute_flags(&ctx->jit, instr->cc);
    arm64_cc_t arm_cc = x86_cc_to_arm64(instr->cc);
    emit_cset(&ctx->jit, false, dst, arm_cc);
    return 0;
}

/* CMOVcc reg, reg/mem */
int pattern_cmovcc(translator_ctx_t *ctx, const x86_instr_t *instr) {
    uint32_t dst = arm_reg(&instr->operands[0]);
    bool sf = is_64bit(instr);

    uint32_t src;
    if (instr->operands[1].type == OPERAND_REG) {
        src = arm_reg(&instr->operands[1]);
    } else if (instr->operands[1].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[1], ctx);
        emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
        src = ARM_SCRATCH1;
    } else {
        return -1;
    }

    emit_compute_flags(&ctx->jit, instr->cc);
    arm64_cc_t arm_cc = x86_cc_to_arm64(instr->cc);
    emit_csel(&ctx->jit, sf, dst, src, dst, arm_cc);
    return 0;
}

/* DIV/IDIV - unsigned/signed division.
 * x86: DIV r/m divides RDX:RAX by operand, quotient in RAX, remainder in RDX */
int pattern_div(translator_ctx_t *ctx, const x86_instr_t *instr) {
    bool sf = is_64bit(instr);
    bool is_signed = (instr->op == X86_OP_IDIV);

    uint32_t divisor;
    if (instr->operands[0].type == OPERAND_REG) {
        divisor = arm_reg(&instr->operands[0]);
    } else if (instr->operands[0].type == OPERAND_MEM) {
        uint32_t addr = emit_lea_to_scratch(&ctx->jit, instr, &instr->operands[0], ctx);
        emit_guest_load(&ctx->jit, ARM_SCRATCH1, addr, instr->op_size);
        divisor = ARM_SCRATCH1;
    } else {
        return -1;
    }

    /* For simplicity, handle single-width division (ignore RDX high part for now).
     * Full RDX:RAX division would need 128-bit support. */
    if (is_signed) {
        emit_sdiv(&ctx->jit, sf, ARM_SCRATCH0, ARM_RAX, divisor);  /* quotient */
    } else {
        emit_udiv(&ctx->jit, sf, ARM_SCRATCH0, ARM_RAX, divisor);  /* quotient */
    }
    /* remainder = RAX - quotient * divisor */
    emit_msub(&ctx->jit, sf, ARM_RDX, ARM_SCRATCH0, divisor, ARM_RAX);
    /* quotient → RAX */
    emit_mov_reg(&ctx->jit, sf, ARM_RAX, ARM_SCRATCH0);

    return 0;
}

/* Dispatch function: given a decoded x86 instruction, call the right pattern */
int translate_instr_direct(translator_ctx_t *ctx, const x86_instr_t *instr) {
    switch (instr->op) {
        case X86_OP_NOP:
            return pattern_nop(ctx, instr);

        case X86_OP_MOV:
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_IMM) {
                return pattern_mov_reg_imm(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_REG) {
                return pattern_mov_reg_reg(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_MEM) {
                return pattern_mov_reg_mem(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_MEM &&
                instr->operands[1].type == OPERAND_REG) {
                return pattern_mov_mem_reg(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_MEM &&
                instr->operands[1].type == OPERAND_IMM) {
                return pattern_mov_mem_imm(ctx, instr);
            }
            return -1;

        case X86_OP_LEA:
            return pattern_lea(ctx, instr);

        case X86_OP_PUSH:
            return pattern_push(ctx, instr);

        case X86_OP_POP:
            return pattern_pop(ctx, instr);

        case X86_OP_ADD: case X86_OP_SUB: case X86_OP_AND:
        case X86_OP_OR:  case X86_OP_XOR: case X86_OP_CMP:
        case X86_OP_TEST:
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_REG) {
                return pattern_alu_reg_reg(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_IMM) {
                return pattern_alu_reg_imm(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_MEM) {
                return pattern_alu_reg_mem(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_MEM &&
                instr->operands[1].type == OPERAND_IMM) {
                return pattern_alu_mem_imm(ctx, instr);
            }
            if (instr->operands[0].type == OPERAND_MEM &&
                instr->operands[1].type == OPERAND_REG) {
                return pattern_alu_mem_reg(ctx, instr);
            }
            return -1;

        case X86_OP_INC:
            return pattern_inc(ctx, instr);
        case X86_OP_DEC:
            return pattern_dec(ctx, instr);
        case X86_OP_NEG:
            return pattern_neg(ctx, instr);
        case X86_OP_NOT:
            return pattern_not(ctx, instr);

        case X86_OP_SHL: case X86_OP_SHR: case X86_OP_SAR:
            return pattern_shift(ctx, instr);

        case X86_OP_IMUL:
            return pattern_imul(ctx, instr);

        case X86_OP_DIV: case X86_OP_IDIV:
            return pattern_div(ctx, instr);

        case X86_OP_MOVZX:
            return pattern_movzx(ctx, instr);

        case X86_OP_MOVSX: case X86_OP_MOVSXD:
            return pattern_movsx(ctx, instr);

        case X86_OP_CDQ: case X86_OP_CQO:
            return pattern_cdq_cqo(ctx, instr);
        case X86_OP_CDQE:
            return pattern_cdqe(ctx, instr);

        case X86_OP_XCHG:
            return pattern_xchg(ctx, instr);

        case X86_OP_JMP:
            if (instr->operands[0].type == OPERAND_REL)
                return pattern_jmp_direct(ctx, instr);
            else
                return pattern_jmp_indirect(ctx, instr);

        case X86_OP_JCC:
            return pattern_jcc(ctx, instr);

        case X86_OP_CALL:
            if (instr->operands[0].type == OPERAND_REL)
                return pattern_call_direct(ctx, instr);
            else
                return pattern_call_indirect(ctx, instr);

        case X86_OP_RET:
            return pattern_ret(ctx, instr);

        case X86_OP_SETCC:
            return pattern_setcc(ctx, instr);

        case X86_OP_CMOVCC:
            return pattern_cmovcc(ctx, instr);

        case X86_OP_SYSCALL:
            /* Set RIP to next instruction before the syscall handler saves state.
             * handle_syscall may override RIP (e.g., exit sets it to 0). */
            emit_mov_imm64(&ctx->jit, ARM_RIP, instr->addr + instr->length);
            emit_syscall(&ctx->jit, ctx);
            /* Return to dispatch loop. RIP was set by handle_syscall
             * (either next instr or 0 for exit). */
            emit_ret(&ctx->jit, ARM_LR);
            return 0;

        default:
            /* Unimplemented instruction */
            LOG_WARN("Unimplemented x86 instruction: %s at 0x%llx",
                     x86_mnemonic_name(instr->op), (unsigned long long)instr->addr);
            ctx->stats.unimplemented_count++;
            /* Emit a breakpoint so we know where translation stopped */
            emit_brk(&ctx->jit, 0xF000 | (instr->op & 0xFFF));
            return -1;
    }
}
