/*
 * ir_opt.c - IR optimization passes
 *
 * Runs optimization passes over IR basic blocks to improve generated code:
 * - Dead flag elimination: remove unused flag computations
 * - Constant folding: evaluate constant expressions at translation time
 * - Redundant load elimination: skip loads of recently stored values
 */

#include "ir.h"
#include "debug.h"

/* Dead flag elimination: walk backwards through the block.
 * If we see a flag-setting instruction (sets_flags) before any flag-reading
 * instruction (reads_flags), the flags computation is dead. */
void ir_opt_dead_flags(ir_block_t *block) {
    if (!block) return;

    bool flags_live = false;

    /* Walk backwards from end of block */
    for (ir_instr_t *instr = block->last; instr; instr = instr->prev) {
        if (instr->dead) continue;

        if (instr->reads_flags) {
            /* This instruction consumes flags - they're live */
            flags_live = true;
        }

        if (instr->sets_flags) {
            if (!flags_live) {
                /* Flags are set but never read before the next flag-setter.
                 * If this is an IR_SET_FLAGS or IR_CMP/IR_TEST, mark it dead.
                 * For combined ops (IR_ADD that also sets flags), we can't
                 * eliminate the instruction, but we could remove the flag part. */
                if (instr->opcode == IR_SET_FLAGS ||
                    instr->opcode == IR_CMP ||
                    instr->opcode == IR_TEST) {
                    instr->dead = true;
                    LOG_DBG("Dead flag elimination: removed %s at x86:0x%llx",
                            ir_opcode_name(instr->opcode),
                            (unsigned long long)instr->x86_addr);
                } else {
                    /* Can't remove the instruction, but clear the sets_flags marker */
                    instr->sets_flags = false;
                }
            }
            /* Whether dead or not, flags are now not live above this point
             * (this instruction defines them, so anything above doesn't matter
             * for the current consumer) */
            flags_live = false;
        }
    }
}

/* Constant folding: if both operands of an arithmetic instruction are
 * immediates, compute the result at translation time. */
void ir_opt_const_fold(ir_block_t *block) {
    if (!block) return;

    for (ir_instr_t *instr = block->first; instr; instr = instr->next) {
        if (instr->dead) continue;

        /* Only fold if both sources are immediates */
        if (instr->src1.type != IR_OP_IMM || instr->src2.type != IR_OP_IMM)
            continue;

        int64_t a = instr->src1.imm;
        int64_t b = instr->src2.imm;
        int64_t result;

        switch (instr->opcode) {
            case IR_ADD:  result = a + b; break;
            case IR_SUB:  result = a - b; break;
            case IR_AND:  result = a & b; break;
            case IR_OR:   result = a | b; break;
            case IR_XOR:  result = a ^ b; break;
            case IR_SHL:  result = a << (b & 63); break;
            case IR_SHR:  result = (int64_t)((uint64_t)a >> (b & 63)); break;
            case IR_MUL:  result = a * b; break;
            default:
                continue;  /* Can't fold this opcode */
        }

        LOG_DBG("Constant fold: %s #0x%llx, #0x%llx → #0x%llx at x86:0x%llx",
                ir_opcode_name(instr->opcode),
                (unsigned long long)a, (unsigned long long)b,
                (unsigned long long)result,
                (unsigned long long)instr->x86_addr);

        /* Replace with MOV dst, #result */
        instr->opcode = IR_MOV;
        instr->src1 = ir_op_imm(result, instr->dst.size);
        instr->src2 = ir_op_none();
    }
}

/* Redundant load elimination: if we see a store to [addr] followed by a load
 * from the same [addr] with no intervening stores, replace the load with a
 * copy of the stored value. */
void ir_opt_load_elim(ir_block_t *block) {
    if (!block) return;

    for (ir_instr_t *instr = block->first; instr; instr = instr->next) {
        if (instr->dead) continue;
        if (instr->opcode != IR_LOAD) continue;

        /* Look backwards for a matching store */
        for (ir_instr_t *prev = instr->prev; prev; prev = prev->prev) {
            if (prev->dead) continue;

            /* If we hit another store to the same address, use its value */
            if (prev->opcode == IR_STORE &&
                prev->dst.type == instr->src1.type &&
                prev->dst.type == IR_OP_MEM &&
                prev->dst.mem.base_vreg == instr->src1.mem.base_vreg &&
                prev->dst.mem.offset == instr->src1.mem.offset) {
                LOG_DBG("Load elimination: replaced LOAD with value from STORE at x86:0x%llx",
                        (unsigned long long)instr->x86_addr);
                instr->opcode = IR_MOV;
                instr->src1 = prev->src1;  /* Use the stored value */
                break;
            }

            /* If we hit any other store, give up (might alias) */
            if (prev->opcode == IR_STORE || prev->opcode == IR_SYSCALL) {
                break;
            }
        }
    }
}

/* Run all optimization passes */
void ir_opt_run(ir_block_t *block) {
    ir_opt_dead_flags(block);
    ir_opt_const_fold(block);
    ir_opt_load_elim(block);
}
