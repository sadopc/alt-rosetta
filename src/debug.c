/*
 * debug.c - Trace and logging utilities
 *
 * Provides configurable logging at multiple severity levels and tracing
 * of decoded x86 instructions, emitted ARM64 instructions, and execution
 * state for debugging the translator.
 */

#include "debug.h"
#include "cpu_state.h"
#include "x86_decode.h"
#include <stdarg.h>

/* Global trace flags - default all disabled */
trace_flags_t g_trace = {
    .trace_decode = false,
    .trace_ir     = false,
    .trace_emit   = false,
    .trace_exec   = false,
};

/* Global log level - default to INFO */
log_level_t g_log_level = LOG_INFO;

/*
 * log_msg - Core logging function.
 *
 * Prints a formatted message to stderr if the given level is at or below
 * the current global log level. Prepends a severity tag.
 */
void log_msg(log_level_t level, const char *fmt, ...)
{
    if (level > g_log_level)
        return;

    static const char *level_tags[] = {
        "[ERROR] ",
        "[WARN]  ",
        "[INFO]  ",
        "[DEBUG] ",
        "[TRACE] ",
    };

    const char *tag = (level <= LOG_TRACE) ? level_tags[level] : "[???]   ";
    fprintf(stderr, "%s", tag);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/*
 * trace_x86_instr - Print a decoded x86 instruction.
 *
 * Format: "x86  | 0x<addr>:  <hex bytes>  <mnemonic>"
 */
void trace_x86_instr(uint64_t addr, const uint8_t *bytes, size_t len, const char *mnemonic)
{
    if (!g_trace.trace_decode)
        return;

    fprintf(stderr, "x86  | 0x%08llx:  ", (unsigned long long)addr);

    /* Print hex bytes (padded to 10 bytes width for alignment) */
    for (size_t i = 0; i < len; i++)
        fprintf(stderr, "%02x ", bytes[i]);
    for (size_t i = len; i < 10; i++)
        fprintf(stderr, "   ");

    fprintf(stderr, " %s\n", mnemonic);
}

/*
 * trace_arm64_instr - Print an emitted ARM64 instruction.
 *
 * Format: "arm64| 0x<addr>:  <hex word>  <description>"
 */
void trace_arm64_instr(uint32_t *addr, uint32_t inst, const char *desc)
{
    if (!g_trace.trace_emit)
        return;

    fprintf(stderr, "arm64| %p:  %08x   %s\n", (void *)addr, inst, desc);
}

/*
 * trace_exec - Print execution trace: RIP and first 4 GPRs.
 *
 * Called before executing each translated block to show the guest state.
 */
void trace_exec(const x86_cpu_state_t *state)
{
    if (!g_trace.trace_exec)
        return;

    fprintf(stderr, "exec | RIP=0x%08llx  RAX=0x%llx  RCX=0x%llx  RDX=0x%llx  RBX=0x%llx\n",
            (unsigned long long)state->rip,
            (unsigned long long)state->gpr[X86_RAX],
            (unsigned long long)state->gpr[X86_RCX],
            (unsigned long long)state->gpr[X86_RDX],
            (unsigned long long)state->gpr[X86_RBX]);
}

/*
 * hexdump - Standard hex dump utility.
 *
 * Prints data in the classic format:
 *   <address>:  <hex bytes>  |<ascii>|
 *
 * 16 bytes per line, with printable ASCII on the right.
 */
void hexdump(const void *data, size_t size, uint64_t base_addr)
{
    const uint8_t *p = (const uint8_t *)data;

    for (size_t offset = 0; offset < size; offset += 16) {
        /* Address */
        fprintf(stderr, "%08llx  ", (unsigned long long)(base_addr + offset));

        /* Hex bytes */
        for (size_t i = 0; i < 16; i++) {
            if (offset + i < size)
                fprintf(stderr, "%02x ", p[offset + i]);
            else
                fprintf(stderr, "   ");
            if (i == 7)
                fprintf(stderr, " ");
        }

        /* ASCII */
        fprintf(stderr, " |");
        for (size_t i = 0; i < 16 && offset + i < size; i++) {
            uint8_t c = p[offset + i];
            fprintf(stderr, "%c", (c >= 0x20 && c <= 0x7E) ? c : '.');
        }
        fprintf(stderr, "|\n");
    }
}

/*
 * x86_mnemonic_name - Return the string name for an x86_op_type_t enum value.
 */
const char *x86_mnemonic_name(int opcode_type)
{
    static const char *names[] = {
        [X86_OP_INVALID] = "INVALID",

        /* Data transfer */
        [X86_OP_MOV]    = "MOV",
        [X86_OP_MOVZX]  = "MOVZX",
        [X86_OP_MOVSX]  = "MOVSX",
        [X86_OP_MOVSXD] = "MOVSXD",
        [X86_OP_LEA]    = "LEA",
        [X86_OP_PUSH]   = "PUSH",
        [X86_OP_POP]    = "POP",
        [X86_OP_XCHG]   = "XCHG",
        [X86_OP_CDQ]    = "CDQ",
        [X86_OP_CQO]    = "CQO",
        [X86_OP_CBW]    = "CBW",
        [X86_OP_CWDE]   = "CWDE",
        [X86_OP_CDQE]   = "CDQE",

        /* Arithmetic */
        [X86_OP_ADD]    = "ADD",
        [X86_OP_SUB]    = "SUB",
        [X86_OP_ADC]    = "ADC",
        [X86_OP_SBB]    = "SBB",
        [X86_OP_INC]    = "INC",
        [X86_OP_DEC]    = "DEC",
        [X86_OP_NEG]    = "NEG",
        [X86_OP_NOT]    = "NOT",
        [X86_OP_MUL]    = "MUL",
        [X86_OP_IMUL]   = "IMUL",
        [X86_OP_DIV]    = "DIV",
        [X86_OP_IDIV]   = "IDIV",

        /* Logic */
        [X86_OP_AND]    = "AND",
        [X86_OP_OR]     = "OR",
        [X86_OP_XOR]    = "XOR",
        [X86_OP_TEST]   = "TEST",

        /* Compare */
        [X86_OP_CMP]    = "CMP",

        /* Shifts/rotates */
        [X86_OP_SHL]    = "SHL",
        [X86_OP_SHR]    = "SHR",
        [X86_OP_SAR]    = "SAR",
        [X86_OP_ROL]    = "ROL",
        [X86_OP_ROR]    = "ROR",
        [X86_OP_RCL]    = "RCL",
        [X86_OP_RCR]    = "RCR",

        /* Control flow */
        [X86_OP_JMP]    = "JMP",
        [X86_OP_JCC]    = "Jcc",
        [X86_OP_CALL]   = "CALL",
        [X86_OP_RET]    = "RET",
        [X86_OP_LOOP]   = "LOOP",
        [X86_OP_LOOPE]  = "LOOPE",
        [X86_OP_LOOPNE] = "LOOPNE",

        /* Conditional set/move */
        [X86_OP_SETCC]  = "SETcc",
        [X86_OP_CMOVCC] = "CMOVcc",

        /* String operations */
        [X86_OP_MOVSB]     = "MOVSB",
        [X86_OP_MOVSW]     = "MOVSW",
        [X86_OP_MOVSD_STR] = "MOVSD",
        [X86_OP_MOVSQ]     = "MOVSQ",
        [X86_OP_STOSB]     = "STOSB",
        [X86_OP_STOSW]     = "STOSW",
        [X86_OP_STOSD]     = "STOSD",
        [X86_OP_STOSQ]     = "STOSQ",
        [X86_OP_LODSB]     = "LODSB",
        [X86_OP_LODSW]     = "LODSW",
        [X86_OP_LODSD]     = "LODSD",
        [X86_OP_LODSQ]     = "LODSQ",
        [X86_OP_CMPSB]     = "CMPSB",
        [X86_OP_SCASB]     = "SCASB",

        /* System */
        [X86_OP_SYSCALL] = "SYSCALL",
        [X86_OP_INT]     = "INT",
        [X86_OP_HLT]     = "HLT",
        [X86_OP_CPUID]   = "CPUID",
        [X86_OP_RDTSC]   = "RDTSC",

        /* Flag manipulation */
        [X86_OP_CLC]    = "CLC",
        [X86_OP_STC]    = "STC",
        [X86_OP_CLD]    = "CLD",
        [X86_OP_STD]    = "STD",
        [X86_OP_CMC]    = "CMC",

        /* SSE scalar */
        [X86_OP_MOVSS]    = "MOVSS",
        [X86_OP_MOVSD]    = "MOVSD",
        [X86_OP_MOVAPS]   = "MOVAPS",
        [X86_OP_MOVUPS]   = "MOVUPS",
        [X86_OP_ADDSS]    = "ADDSS",
        [X86_OP_ADDSD]    = "ADDSD",
        [X86_OP_SUBSS]    = "SUBSS",
        [X86_OP_SUBSD]    = "SUBSD",
        [X86_OP_MULSS]    = "MULSS",
        [X86_OP_MULSD]    = "MULSD",
        [X86_OP_DIVSS]    = "DIVSS",
        [X86_OP_DIVSD]    = "DIVSD",
        [X86_OP_SQRTSS]   = "SQRTSS",
        [X86_OP_SQRTSD]   = "SQRTSD",
        [X86_OP_UCOMISS]  = "UCOMISS",
        [X86_OP_UCOMISD]  = "UCOMISD",
        [X86_OP_CVTSI2SS] = "CVTSI2SS",
        [X86_OP_CVTSI2SD] = "CVTSI2SD",
        [X86_OP_CVTSS2SI] = "CVTSS2SI",
        [X86_OP_CVTSD2SI] = "CVTSD2SI",
        [X86_OP_CVTSS2SD] = "CVTSS2SD",
        [X86_OP_CVTSD2SS] = "CVTSD2SS",
        [X86_OP_XORPS]    = "XORPS",
        [X86_OP_XORPD]    = "XORPD",
        [X86_OP_ANDPS]    = "ANDPS",
        [X86_OP_ORPS]     = "ORPS",
        [X86_OP_PXOR]     = "PXOR",

        /* SSE packed */
        [X86_OP_ADDPS]  = "ADDPS",
        [X86_OP_ADDPD]  = "ADDPD",
        [X86_OP_SUBPS]  = "SUBPS",
        [X86_OP_SUBPD]  = "SUBPD",
        [X86_OP_MULPS]  = "MULPS",
        [X86_OP_MULPD]  = "MULPD",
        [X86_OP_PADDB]  = "PADDB",
        [X86_OP_PADDW]  = "PADDW",
        [X86_OP_PADDD]  = "PADDD",
        [X86_OP_PADDQ]  = "PADDQ",

        /* NOP */
        [X86_OP_NOP]    = "NOP",
    };

    if (opcode_type >= 0 && opcode_type < (int)(sizeof(names) / sizeof(names[0])) && names[opcode_type])
        return names[opcode_type];

    return "UNKNOWN";
}
