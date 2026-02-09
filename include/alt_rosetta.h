/*
 * alt_rosetta.h - Alternative Rosetta: Educational x86_64 → ARM64 Binary Translator
 *
 * Master include file with version info, configuration, and common types.
 */

#ifndef ALT_ROSETTA_H
#define ALT_ROSETTA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ALT_ROSETTA_VERSION_MAJOR 0
#define ALT_ROSETTA_VERSION_MINOR 1
#define ALT_ROSETTA_VERSION_PATCH 0
#define ALT_ROSETTA_VERSION_STRING "0.1.0"

/* Default JIT code buffer size: 64 MB */
#define JIT_CODE_SIZE       (64 * 1024 * 1024)

/* Default guest stack size: 8 MB */
#define GUEST_STACK_SIZE    (8 * 1024 * 1024)

/* Translation cache default capacity (power of 2) */
#define CACHE_DEFAULT_CAP   (1 << 16)

/* Maximum basic block size (instructions) */
#define MAX_BLOCK_SIZE      256

/* Maximum IR instructions per basic block */
#define MAX_IR_PER_BLOCK    2048

/* x86_64 register indices */
enum {
    X86_RAX = 0,  X86_RCX = 1,  X86_RDX = 2,  X86_RBX = 3,
    X86_RSP = 4,  X86_RBP = 5,  X86_RSI = 6,  X86_RDI = 7,
    X86_R8  = 8,  X86_R9  = 9,  X86_R10 = 10, X86_R11 = 11,
    X86_R12 = 12, X86_R13 = 13, X86_R14 = 14, X86_R15 = 15,
    X86_REG_COUNT = 16
};

/* ARM64 register assignments for x86 guest state.
 * x86 GPRs are mapped into ARM64 X0-X15.
 * X16-X17: scratch/trampolines
 * X18: RESERVED (macOS platform register - never touch)
 * X19: lazy flags operation type
 * X20: emulated RIP
 * X21: translator context pointer
 * X22-X24: temporaries for complex translations
 * X25: lazy flags operand 1
 * X26: lazy flags operand 2
 * X27: lazy flags result
 * X28: lazy flags operand size
 * X29: host frame pointer (ARM64 ABI)
 * X30: host link register (ARM64 ABI)
 * V0-V15: XMM0-XMM15
 */
enum {
    /* x86 GPR → ARM64 register mapping */
    ARM_RAX = 0,   /* X0  ← RAX */
    ARM_RCX = 1,   /* X1  ← RCX */
    ARM_RDX = 2,   /* X2  ← RDX */
    ARM_RBX = 3,   /* X3  ← RBX */
    ARM_RSI = 4,   /* X4  ← RSI */
    ARM_RDI = 5,   /* X5  ← RDI */
    ARM_RSP = 6,   /* X6  ← RSP (guest stack pointer, NOT ARM SP) */
    ARM_RBP = 7,   /* X7  ← RBP */
    ARM_R8  = 8,   /* X8  ← R8  */
    ARM_R9  = 9,   /* X9  ← R9  */
    ARM_R10 = 10,  /* X10 ← R10 */
    ARM_R11 = 11,  /* X11 ← R11 */
    ARM_R12 = 12,  /* X12 ← R12 */
    ARM_R13 = 13,  /* X13 ← R13 */
    ARM_R14 = 14,  /* X14 ← R14 */
    ARM_R15 = 15,  /* X15 ← R15 */

    /* Special-purpose ARM64 registers */
    ARM_SCRATCH0    = 16, /* X16 - scratch */
    ARM_SCRATCH1    = 17, /* X17 - scratch */
    /* X18 is reserved by macOS - never use */
    ARM_FLAGS_OP    = 19, /* X19 - lazy flags: operation type */
    ARM_RIP         = 20, /* X20 - emulated RIP */
    ARM_CTX         = 21, /* X21 - translator context pointer */
    ARM_TMP0        = 22, /* X22 - temp */
    ARM_TMP1        = 23, /* X23 - temp */
    ARM_TMP2        = 24, /* X24 - temp */
    ARM_FLAGS_OP1   = 25, /* X25 - lazy flags: operand 1 */
    ARM_FLAGS_OP2   = 26, /* X26 - lazy flags: operand 2 */
    ARM_FLAGS_RES   = 27, /* X27 - lazy flags: result */
    ARM_FLAGS_SIZE  = 28, /* X28 - lazy flags: operand size */
    ARM_FP          = 29, /* X29 - host frame pointer */
    ARM_LR          = 30, /* X30 - host link register */
    ARM_SP          = 31, /* SP  - host stack pointer (zero reg in some encodings) */
};

/* x86 GPR index → ARM64 register number */
static inline uint32_t x86_to_arm_reg(int x86_reg) {
    /*
     * Mapping: RAX→X0, RCX→X1, RDX→X2, RBX→X3,
     *          RSP→X6, RBP→X7, RSI→X4, RDI→X5,
     *          R8-R15 → X8-X15
     */
    static const uint32_t map[16] = {
        0,  1,  2,  3,   /* RAX, RCX, RDX, RBX */
        6,  7,  4,  5,   /* RSP, RBP, RSI, RDI */
        8,  9,  10, 11,  /* R8-R11 */
        12, 13, 14, 15   /* R12-R15 */
    };
    return map[x86_reg & 0xF];
}

/* Operand sizes */
typedef enum {
    SIZE_8  = 1,
    SIZE_16 = 2,
    SIZE_32 = 4,
    SIZE_64 = 8,
} operand_size_t;

/* Trace/debug flags */
typedef struct {
    bool trace_decode;  /* Print each decoded x86 instruction */
    bool trace_ir;      /* Print IR after translation */
    bool trace_emit;    /* Print each emitted ARM64 instruction */
    bool trace_exec;    /* Print execution trace (RIP + register state) */
} trace_flags_t;

/* Forward declarations */
typedef struct x86_cpu_state x86_cpu_state_t;
typedef struct translator_ctx translator_ctx_t;
typedef struct jit_memory jit_memory_t;
typedef struct trans_cache trans_cache_t;
typedef struct macho_binary macho_binary_t;
typedef struct x86_instr x86_instr_t;
typedef struct ir_instr ir_instr_t;
typedef struct ir_block ir_block_t;

#endif /* ALT_ROSETTA_H */
