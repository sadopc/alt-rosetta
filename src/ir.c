/*
 * ir.c - Intermediate Representation construction
 *
 * Builds IR from decoded x86 instructions. The IR serves as an optimization
 * layer between x86 decoding and ARM64 emission.
 */

#include "ir.h"
#include "debug.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Opcode names for debugging */
static const char *ir_opcode_names[] = {
    [IR_NOP]            = "NOP",
    [IR_MOV]            = "MOV",
    [IR_LOAD]           = "LOAD",
    [IR_STORE]          = "STORE",
    [IR_LOAD_CTX]       = "LOAD_CTX",
    [IR_STORE_CTX]      = "STORE_CTX",
    [IR_ADD]            = "ADD",
    [IR_SUB]            = "SUB",
    [IR_MUL]            = "MUL",
    [IR_IMUL]           = "IMUL",
    [IR_DIV]            = "DIV",
    [IR_IDIV]           = "IDIV",
    [IR_NEG]            = "NEG",
    [IR_INC]            = "INC",
    [IR_DEC]            = "DEC",
    [IR_AND]            = "AND",
    [IR_OR]             = "OR",
    [IR_XOR]            = "XOR",
    [IR_NOT]            = "NOT",
    [IR_TEST]           = "TEST",
    [IR_SHL]            = "SHL",
    [IR_SHR]            = "SHR",
    [IR_SAR]            = "SAR",
    [IR_CMP]            = "CMP",
    [IR_SET_FLAGS]      = "SET_FLAGS",
    [IR_GET_FLAG]       = "GET_FLAG",
    [IR_SET_FLAG_DIRECT]= "SET_FLAG_DIRECT",
    [IR_JUMP]           = "JUMP",
    [IR_JUMP_CC]        = "JUMP_CC",
    [IR_CALL]           = "CALL",
    [IR_RET]            = "RET",
    [IR_SYSCALL]        = "SYSCALL",
    [IR_ZEXT]           = "ZEXT",
    [IR_SEXT]           = "SEXT",
    [IR_PUSH]           = "PUSH",
    [IR_POP]            = "POP",
    [IR_LEA]            = "LEA",
    [IR_FADD]           = "FADD",
    [IR_FSUB]           = "FSUB",
    [IR_FMUL]           = "FMUL",
    [IR_FDIV]           = "FDIV",
    [IR_FSQRT]          = "FSQRT",
    [IR_FCMP]           = "FCMP",
    [IR_BLOCK_END]      = "BLOCK_END",
    [IR_UNIMPLEMENTED]  = "UNIMPLEMENTED",
};

const char *ir_opcode_name(ir_opcode_t op) {
    if (op >= 0 && op < IR_OP_COUNT && ir_opcode_names[op]) {
        return ir_opcode_names[op];
    }
    return "???";
}

/* Create a new empty IR block */
ir_block_t *ir_block_create(uint64_t start_addr) {
    ir_block_t *block = calloc(1, sizeof(ir_block_t));
    if (!block) return NULL;
    block->start_addr = start_addr;
    block->next_vreg = X86_REG_COUNT;  /* Reserve 0-15 for x86 GPRs */
    return block;
}

/* Append an IR instruction to a block */
ir_instr_t *ir_emit(ir_block_t *block, ir_opcode_t op,
                    ir_operand_t dst, ir_operand_t src1, ir_operand_t src2) {
    ir_instr_t *instr = calloc(1, sizeof(ir_instr_t));
    if (!instr) return NULL;

    instr->opcode = op;
    instr->dst = dst;
    instr->src1 = src1;
    instr->src2 = src2;

    /* Insert at end of linked list */
    instr->prev = block->last;
    instr->next = NULL;
    if (block->last) {
        block->last->next = instr;
    } else {
        block->first = instr;
    }
    block->last = instr;
    block->count++;

    return instr;
}

/* Helper: create operands */
ir_operand_t ir_op_none(void) {
    ir_operand_t op = {0};
    op.type = IR_OP_NONE;
    return op;
}

ir_operand_t ir_op_vreg(uint32_t vreg, operand_size_t size) {
    ir_operand_t op = {0};
    op.type = IR_OP_VREG;
    op.size = size;
    op.vreg = vreg;
    return op;
}

ir_operand_t ir_op_imm(int64_t value, operand_size_t size) {
    ir_operand_t op = {0};
    op.type = IR_OP_IMM;
    op.size = size;
    op.imm = value;
    return op;
}

ir_operand_t ir_op_mem(uint32_t base, int64_t offset, operand_size_t size) {
    ir_operand_t op = {0};
    op.type = IR_OP_MEM;
    op.size = size;
    op.mem.base_vreg = base;
    op.mem.offset = offset;
    return op;
}

ir_operand_t ir_op_label(uint64_t addr) {
    ir_operand_t op = {0};
    op.type = IR_OP_LABEL;
    op.label = addr;
    return op;
}

ir_operand_t ir_op_cc(x86_cc_t cc) {
    ir_operand_t op = {0};
    op.type = IR_OP_CC;
    op.cc = cc;
    return op;
}

uint32_t ir_alloc_vreg(ir_block_t *block) {
    return block->next_vreg++;
}

uint32_t ir_x86_reg_vreg(int x86_reg) {
    return (uint32_t)(x86_reg & 0xF);
}

/* Lower a decoded x86 instruction to IR.
 * This is a simplified version covering the most common instructions. */
int ir_lower_x86(ir_block_t *block, const x86_instr_t *instr) {
    operand_size_t sz = instr->op_size;

    switch (instr->op) {
        case X86_OP_NOP:
            ir_emit(block, IR_NOP, ir_op_none(), ir_op_none(), ir_op_none());
            break;

        case X86_OP_MOV:
            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_IMM) {
                uint32_t dst = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_emit(block, IR_MOV,
                        ir_op_vreg(dst, sz),
                        ir_op_imm(instr->operands[1].imm.value, sz),
                        ir_op_none());
            } else if (instr->operands[0].type == OPERAND_REG &&
                       instr->operands[1].type == OPERAND_REG) {
                uint32_t dst = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                uint32_t src = ir_x86_reg_vreg(instr->operands[1].reg.reg);
                ir_emit(block, IR_MOV,
                        ir_op_vreg(dst, sz),
                        ir_op_vreg(src, sz),
                        ir_op_none());
            } else {
                goto unimplemented;
            }
            break;

        case X86_OP_ADD:
        case X86_OP_SUB:
        case X86_OP_AND:
        case X86_OP_OR:
        case X86_OP_XOR: {
            ir_opcode_t ir_op;
            switch (instr->op) {
                case X86_OP_ADD: ir_op = IR_ADD; break;
                case X86_OP_SUB: ir_op = IR_SUB; break;
                case X86_OP_AND: ir_op = IR_AND; break;
                case X86_OP_OR:  ir_op = IR_OR;  break;
                case X86_OP_XOR: ir_op = IR_XOR; break;
                default: goto unimplemented;
            }

            if (instr->operands[0].type == OPERAND_REG &&
                instr->operands[1].type == OPERAND_REG) {
                uint32_t dst = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                uint32_t src = ir_x86_reg_vreg(instr->operands[1].reg.reg);
                ir_instr_t *ir = ir_emit(block, ir_op,
                        ir_op_vreg(dst, sz),
                        ir_op_vreg(dst, sz),
                        ir_op_vreg(src, sz));
                if (ir) ir->sets_flags = true;
            } else if (instr->operands[0].type == OPERAND_REG &&
                       instr->operands[1].type == OPERAND_IMM) {
                uint32_t dst = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_instr_t *ir = ir_emit(block, ir_op,
                        ir_op_vreg(dst, sz),
                        ir_op_vreg(dst, sz),
                        ir_op_imm(instr->operands[1].imm.value, sz));
                if (ir) ir->sets_flags = true;
            } else {
                goto unimplemented;
            }
            break;
        }

        case X86_OP_CMP: {
            if (instr->operands[0].type == OPERAND_REG) {
                uint32_t r1 = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_operand_t src2;
                if (instr->operands[1].type == OPERAND_REG) {
                    src2 = ir_op_vreg(ir_x86_reg_vreg(instr->operands[1].reg.reg), sz);
                } else if (instr->operands[1].type == OPERAND_IMM) {
                    src2 = ir_op_imm(instr->operands[1].imm.value, sz);
                } else {
                    goto unimplemented;
                }
                ir_instr_t *ir = ir_emit(block, IR_CMP,
                        ir_op_none(), ir_op_vreg(r1, sz), src2);
                if (ir) ir->sets_flags = true;
            } else {
                goto unimplemented;
            }
            break;
        }

        case X86_OP_TEST: {
            if (instr->operands[0].type == OPERAND_REG) {
                uint32_t r1 = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_operand_t src2;
                if (instr->operands[1].type == OPERAND_REG) {
                    src2 = ir_op_vreg(ir_x86_reg_vreg(instr->operands[1].reg.reg), sz);
                } else if (instr->operands[1].type == OPERAND_IMM) {
                    src2 = ir_op_imm(instr->operands[1].imm.value, sz);
                } else {
                    goto unimplemented;
                }
                ir_instr_t *ir = ir_emit(block, IR_TEST,
                        ir_op_none(), ir_op_vreg(r1, sz), src2);
                if (ir) ir->sets_flags = true;
            } else {
                goto unimplemented;
            }
            break;
        }

        case X86_OP_JMP:
            if (instr->operands[0].type == OPERAND_REL) {
                uint64_t target = instr->addr + instr->length + instr->operands[0].rel.offset;
                ir_emit(block, IR_JUMP, ir_op_none(), ir_op_label(target), ir_op_none());
            } else {
                goto unimplemented;
            }
            break;

        case X86_OP_JCC: {
            uint64_t target = instr->addr + instr->length + instr->operands[0].rel.offset;
            ir_instr_t *ir = ir_emit(block, IR_JUMP_CC,
                    ir_op_none(), ir_op_label(target), ir_op_cc(instr->cc));
            if (ir) ir->reads_flags = true;
            break;
        }

        case X86_OP_CALL:
            if (instr->operands[0].type == OPERAND_REL) {
                uint64_t target = instr->addr + instr->length + instr->operands[0].rel.offset;
                ir_emit(block, IR_CALL, ir_op_none(), ir_op_label(target), ir_op_none());
            } else {
                goto unimplemented;
            }
            break;

        case X86_OP_RET:
            ir_emit(block, IR_RET, ir_op_none(), ir_op_none(), ir_op_none());
            break;

        case X86_OP_SYSCALL:
            ir_emit(block, IR_SYSCALL, ir_op_none(), ir_op_none(), ir_op_none());
            break;

        case X86_OP_PUSH:
            if (instr->operands[0].type == OPERAND_REG) {
                uint32_t src = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_emit(block, IR_PUSH, ir_op_none(), ir_op_vreg(src, SIZE_64), ir_op_none());
            } else if (instr->operands[0].type == OPERAND_IMM) {
                ir_emit(block, IR_PUSH, ir_op_none(),
                        ir_op_imm(instr->operands[0].imm.value, SIZE_64), ir_op_none());
            } else {
                goto unimplemented;
            }
            break;

        case X86_OP_POP:
            if (instr->operands[0].type == OPERAND_REG) {
                uint32_t dst = ir_x86_reg_vreg(instr->operands[0].reg.reg);
                ir_emit(block, IR_POP, ir_op_vreg(dst, SIZE_64), ir_op_none(), ir_op_none());
            } else {
                goto unimplemented;
            }
            break;

        default:
        unimplemented:
            ir_emit(block, IR_UNIMPLEMENTED,
                    ir_op_imm(instr->op, SIZE_64),
                    ir_op_imm((int64_t)instr->addr, SIZE_64),
                    ir_op_none());
            return -1;
    }

    /* Tag the last emitted instruction with the source x86 address */
    if (block->last) {
        block->last->x86_addr = instr->addr;
    }

    return 0;
}

/* Free an IR block */
void ir_block_free(ir_block_t *block) {
    if (!block) return;
    ir_instr_t *curr = block->first;
    while (curr) {
        ir_instr_t *next = curr->next;
        free(curr);
        curr = next;
    }
    free(block);
}

/* Dump an IR block for debugging */
void ir_block_dump(const ir_block_t *block) {
    if (!block) return;
    fprintf(stderr, "=== IR Block [0x%llx - 0x%llx] (%d instructions) ===\n",
            (unsigned long long)block->start_addr,
            (unsigned long long)block->end_addr,
            block->count);

    int idx = 0;
    for (ir_instr_t *instr = block->first; instr; instr = instr->next, idx++) {
        fprintf(stderr, "  %3d: %s%s", idx, ir_opcode_name(instr->opcode),
                instr->dead ? " [DEAD]" : "");

        /* Print operands */
        ir_operand_t ops[] = {instr->dst, instr->src1, instr->src2};
        for (int i = 0; i < 3; i++) {
            if (ops[i].type == IR_OP_NONE) continue;
            fprintf(stderr, "%s", i == 0 ? " " : ", ");
            switch (ops[i].type) {
                case IR_OP_VREG:
                    fprintf(stderr, "v%u:%d", ops[i].vreg, ops[i].size);
                    break;
                case IR_OP_IMM:
                    fprintf(stderr, "#0x%llx", (unsigned long long)ops[i].imm);
                    break;
                case IR_OP_MEM:
                    fprintf(stderr, "[v%u+%lld]:%d",
                            ops[i].mem.base_vreg,
                            (long long)ops[i].mem.offset,
                            ops[i].size);
                    break;
                case IR_OP_LABEL:
                    fprintf(stderr, "@0x%llx", (unsigned long long)ops[i].label);
                    break;
                case IR_OP_CC:
                    fprintf(stderr, "cc:%s", x86_cc_name(ops[i].cc));
                    break;
                default:
                    break;
            }
        }

        if (instr->sets_flags) fprintf(stderr, " [FLAGS]");
        fprintf(stderr, "\n");
    }
}
