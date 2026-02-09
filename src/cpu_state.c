/*
 * cpu_state.c - Emulated x86_64 CPU state management
 *
 * Initializes, dumps, and queries the guest x86_64 register file.
 */

#include "cpu_state.h"
#include "debug.h"

void cpu_state_init(x86_cpu_state_t *state, uint64_t entry_point, uint64_t stack_top)
{
    /* Zero the entire structure first */
    memset(state, 0, sizeof(*state));

    /* Set initial instruction pointer */
    state->rip = entry_point;

    /* Set stack pointer */
    state->gpr[X86_RSP] = stack_top;

    /* No lazy flags yet */
    state->flags_op = FLAGS_OP_NONE;
    state->flags_size = 0;

    /* Default MXCSR: all exceptions masked, round-to-nearest */
    state->mxcsr = 0x1F80;

    /* Direction flag clear (forward string operations) */
    state->direction_flag = false;
}

void cpu_state_dump(const x86_cpu_state_t *state)
{
    static const char *gpr_names[X86_REG_COUNT] = {
        "RAX", "RCX", "RDX", "RBX",
        "RSP", "RBP", "RSI", "RDI",
        "R8 ", "R9 ", "R10", "R11",
        "R12", "R13", "R14", "R15"
    };

    fprintf(stderr, "--- x86_64 CPU State ---\n");
    fprintf(stderr, "RIP = 0x%016llx\n", (unsigned long long)state->rip);

    for (int i = 0; i < X86_REG_COUNT; i++) {
        fprintf(stderr, "%s = 0x%016llx", gpr_names[i],
                (unsigned long long)state->gpr[i]);
        if ((i & 1) == 1)
            fprintf(stderr, "\n");
        else
            fprintf(stderr, "    ");
    }

    /* Lazy flags state */
    fprintf(stderr, "Flags: op=%d op1=0x%llx op2=0x%llx res=0x%llx size=%u\n",
            state->flags_op,
            (unsigned long long)state->flags_op1,
            (unsigned long long)state->flags_op2,
            (unsigned long long)state->flags_res,
            state->flags_size);

    /* XMM0-3 (low 64 bits only for brevity) */
    for (int i = 0; i < 4; i++) {
        uint64_t lo = (uint64_t)(state->xmm[i] & 0xFFFFFFFFFFFFFFFFULL);
        uint64_t hi = (uint64_t)(state->xmm[i] >> 64);
        fprintf(stderr, "XMM%d = 0x%016llx_%016llx\n", i,
                (unsigned long long)hi, (unsigned long long)lo);
    }

    fprintf(stderr, "MXCSR = 0x%08x  DF=%d\n", state->mxcsr, state->direction_flag);
    fprintf(stderr, "FS_BASE = 0x%016llx  GS_BASE = 0x%016llx\n",
            (unsigned long long)state->fs_base,
            (unsigned long long)state->gs_base);
    fprintf(stderr, "------------------------\n");
}

const char *x86_reg_name(int reg, operand_size_t size)
{
    /* 64-bit register names */
    static const char *names64[X86_REG_COUNT] = {
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
        "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15"
    };

    /* 32-bit register names */
    static const char *names32[X86_REG_COUNT] = {
        "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
        "r8d", "r9d", "r10d","r11d","r12d","r13d","r14d","r15d"
    };

    /* 16-bit register names */
    static const char *names16[X86_REG_COUNT] = {
        "ax",  "cx",  "dx",  "bx",  "sp",  "bp",  "si",  "di",
        "r8w", "r9w", "r10w","r11w","r12w","r13w","r14w","r15w"
    };

    /* 8-bit register names */
    static const char *names8[X86_REG_COUNT] = {
        "al",  "cl",  "dl",  "bl",  "spl", "bpl", "sil", "dil",
        "r8b", "r9b", "r10b","r11b","r12b","r13b","r14b","r15b"
    };

    if (reg < 0 || reg >= X86_REG_COUNT)
        return "???";

    switch (size) {
    case SIZE_64: return names64[reg];
    case SIZE_32: return names32[reg];
    case SIZE_16: return names16[reg];
    case SIZE_8:  return names8[reg];
    default:      return "???";
    }
}
