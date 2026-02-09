/*
 * ir.h - Intermediate Representation for binary translation
 *
 * x86 instructions are first lowered to IR, then optimized, then lowered to ARM64.
 * This decouples x86 decoding from ARM64 emission and enables optimizations like
 * dead flag elimination and constant folding.
 */

#ifndef IR_H
#define IR_H

#include "alt_rosetta.h"
#include "x86_decode.h"

/* IR opcodes */
typedef enum {
    IR_NOP = 0,

    /* Data movement */
    IR_MOV,             /* dst = src */
    IR_LOAD,            /* dst = *src (memory load) */
    IR_STORE,           /* *dst = src (memory store) */
    IR_LOAD_CTX,        /* dst = cpu_state.field[offset] */
    IR_STORE_CTX,       /* cpu_state.field[offset] = src */

    /* Arithmetic */
    IR_ADD,
    IR_SUB,
    IR_MUL,
    IR_IMUL,
    IR_DIV,
    IR_IDIV,
    IR_NEG,
    IR_INC,
    IR_DEC,

    /* Logic */
    IR_AND,
    IR_OR,
    IR_XOR,
    IR_NOT,
    IR_TEST,            /* AND but discard result, only set flags */

    /* Shifts */
    IR_SHL,
    IR_SHR,
    IR_SAR,

    /* Comparison */
    IR_CMP,             /* SUB but discard result, only set flags */

    /* Flags */
    IR_SET_FLAGS,       /* Record lazy flags state (op, op1, op2, result, size) */
    IR_GET_FLAG,        /* Compute a specific flag from lazy state */
    IR_SET_FLAG_DIRECT, /* Set a specific NZCV flag directly */

    /* Control flow */
    IR_JUMP,            /* Unconditional jump to address */
    IR_JUMP_CC,         /* Conditional jump (condition code + target) */
    IR_CALL,            /* Call to address (push return addr, jump) */
    IR_RET,             /* Return (pop addr, jump) */

    /* System */
    IR_SYSCALL,         /* System call */

    /* Sign/zero extension */
    IR_ZEXT,            /* Zero-extend */
    IR_SEXT,            /* Sign-extend */

    /* Special */
    IR_PUSH,            /* Push to guest stack */
    IR_POP,             /* Pop from guest stack */
    IR_LEA,             /* Load effective address */

    /* SIMD (simplified) */
    IR_FADD,
    IR_FSUB,
    IR_FMUL,
    IR_FDIV,
    IR_FSQRT,
    IR_FCMP,

    /* Block boundary / translation control */
    IR_BLOCK_END,       /* End of basic block */
    IR_UNIMPLEMENTED,   /* Placeholder for unhandled instructions */

    IR_OP_COUNT
} ir_opcode_t;

/* IR operand types */
typedef enum {
    IR_OP_NONE = 0,
    IR_OP_VREG,     /* Virtual register (mapped to physical later) */
    IR_OP_IMM,      /* Immediate constant */
    IR_OP_MEM,      /* Memory address (base + offset) */
    IR_OP_LABEL,    /* Branch target */
    IR_OP_CC,       /* Condition code */
} ir_operand_type_t;

/* IR operand */
typedef struct {
    ir_operand_type_t type;
    operand_size_t    size;
    union {
        uint32_t    vreg;       /* Virtual register number */
        int64_t     imm;        /* Immediate value */
        struct {
            uint32_t base_vreg; /* Base register */
            int64_t  offset;    /* Offset */
            uint8_t  scale;     /* Scale factor (1,2,4,8) */
            uint32_t index_vreg;/* Index register (0 = none) */
        } mem;
        uint64_t    label;      /* Target address */
        x86_cc_t    cc;         /* Condition code */
    };
} ir_operand_t;

/* IR instruction */
struct ir_instr {
    ir_opcode_t     opcode;
    ir_operand_t    dst;
    ir_operand_t    src1;
    ir_operand_t    src2;

    /* Source x86 instruction address (for debug/trace) */
    uint64_t        x86_addr;

    /* Flags metadata */
    bool            sets_flags;     /* Does this instruction set flags? */
    bool            reads_flags;    /* Does this instruction read flags? */
    bool            dead;           /* Marked dead by optimization (skip emission) */

    /* Linked list */
    ir_instr_t     *next;
    ir_instr_t     *prev;
};

/* IR basic block */
struct ir_block {
    ir_instr_t     *first;
    ir_instr_t     *last;
    int             count;          /* Number of instructions */

    /* Guest address range */
    uint64_t        start_addr;     /* x86 start address */
    uint64_t        end_addr;       /* x86 end address (exclusive) */

    /* Next virtual register number */
    uint32_t        next_vreg;
};

/* Create a new empty IR block */
ir_block_t *ir_block_create(uint64_t start_addr);

/* Append an IR instruction to a block */
ir_instr_t *ir_emit(ir_block_t *block, ir_opcode_t op,
                    ir_operand_t dst, ir_operand_t src1, ir_operand_t src2);

/* Helper to create operands */
ir_operand_t ir_op_none(void);
ir_operand_t ir_op_vreg(uint32_t vreg, operand_size_t size);
ir_operand_t ir_op_imm(int64_t value, operand_size_t size);
ir_operand_t ir_op_mem(uint32_t base, int64_t offset, operand_size_t size);
ir_operand_t ir_op_label(uint64_t addr);
ir_operand_t ir_op_cc(x86_cc_t cc);

/* Allocate a new virtual register in a block */
uint32_t ir_alloc_vreg(ir_block_t *block);

/* Convert an x86 register index to an IR virtual register.
 * Uses a fixed mapping so that vregs 0-15 correspond to x86 GPRs 0-15. */
uint32_t ir_x86_reg_vreg(int x86_reg);

/* Lower a decoded x86 instruction to IR instructions in the block.
 * Returns 0 on success, -1 if the instruction is unhandled. */
int ir_lower_x86(ir_block_t *block, const x86_instr_t *instr);

/* Free an IR block and all its instructions */
void ir_block_free(ir_block_t *block);

/* Dump an IR block to stderr (for debugging) */
void ir_block_dump(const ir_block_t *block);

/* Get the string name for an IR opcode */
const char *ir_opcode_name(ir_opcode_t op);

/* ---- Optimization passes (ir_opt.c) ---- */

/* Dead flag elimination: remove IR_SET_FLAGS instructions whose flags
 * are never consumed before the next flag-setting instruction. */
void ir_opt_dead_flags(ir_block_t *block);

/* Constant folding: evaluate IR instructions with all-immediate operands
 * at translation time, replacing them with IR_MOV of the result. */
void ir_opt_const_fold(ir_block_t *block);

/* Redundant load elimination: skip loads of values that were just stored. */
void ir_opt_load_elim(ir_block_t *block);

/* Run all optimization passes */
void ir_opt_run(ir_block_t *block);

#endif /* IR_H */
