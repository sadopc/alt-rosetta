/*
 * cpu_state.h - Emulated x86_64 CPU state
 *
 * Holds the full x86_64 register file, instruction pointer, lazy flags state,
 * SSE registers, and segment bases. This is the "guest" state that the
 * translator maintains.
 */

#ifndef CPU_STATE_H
#define CPU_STATE_H

#include "alt_rosetta.h"

/* Lazy flags operation types - determines how to compute EFLAGS from stored operands */
typedef enum {
    FLAGS_OP_NONE = 0,  /* Flags are invalid / not yet set */
    FLAGS_OP_ADD,
    FLAGS_OP_SUB,       /* Also used for CMP */
    FLAGS_OP_AND,       /* Also used for TEST */
    FLAGS_OP_OR,
    FLAGS_OP_XOR,
    FLAGS_OP_INC,
    FLAGS_OP_DEC,
    FLAGS_OP_SHL,
    FLAGS_OP_SHR,
    FLAGS_OP_SAR,
    FLAGS_OP_IMUL,
    FLAGS_OP_NEG,
    FLAGS_OP_COUNT
} flags_op_t;

/* x86_64 CPU state */
struct x86_cpu_state {
    /* General-purpose registers (indexed by X86_RAX..X86_R15) */
    uint64_t gpr[X86_REG_COUNT];

    /* Instruction pointer */
    uint64_t rip;

    /* Lazy flags state - we defer EFLAGS computation until a consumer reads them.
     * When an arithmetic/logic instruction executes, we store:
     *   flags_op:   which operation produced the flags
     *   flags_op1:  first operand (before operation)
     *   flags_op2:  second operand (before operation)
     *   flags_res:  result of the operation
     *   flags_size: operand size (1/2/4/8 bytes)
     * When a conditional branch/cmov/setcc needs a flag, we compute it on demand. */
    flags_op_t  flags_op;
    uint64_t    flags_op1;
    uint64_t    flags_op2;
    uint64_t    flags_res;
    uint8_t     flags_size;

    /* SSE registers (XMM0-XMM15), each 128 bits */
    __uint128_t xmm[16];

    /* MXCSR: SSE control/status register */
    uint32_t mxcsr;

    /* Segment base addresses (used by some x86_64 code, especially FS for TLS) */
    uint64_t fs_base;
    uint64_t gs_base;

    /* Direction flag (DF in EFLAGS) - affects string operations */
    bool direction_flag;
};

/* Initialize CPU state to a clean reset state */
void cpu_state_init(x86_cpu_state_t *state, uint64_t entry_point, uint64_t stack_top);

/* Dump register state to stderr (for debugging) */
void cpu_state_dump(const x86_cpu_state_t *state);

/* Get a string name for a register index */
const char *x86_reg_name(int reg, operand_size_t size);

#endif /* CPU_STATE_H */
