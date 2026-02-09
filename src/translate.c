/*
 * translate.c - Main translation engine
 *
 * Orchestrates the entire binary translation pipeline:
 * 1. Load x86_64 Mach-O binary
 * 2. Initialize JIT memory, cache, CPU state
 * 3. Translation loop: decode → translate → cache → execute → repeat
 */

#include "translate.h"
#include "macho_loader.h"
#include "x86_decode.h"
#include "x86_tables.h"
#include "arm64_emit.h"
#include "memory.h"
#include "cache.h"
#include "flags.h"
#include "syscall.h"
#include "signal_handler.h"
#include "debug.h"

#include <sys/mman.h>

/* Assembly trampoline: enter translated code.
 *
 * Strategy: Use x21 (translator context pointer) to hold the CPU state base
 * address throughout. We save it to the stack first so it survives the
 * register loading phase.
 *
 * The translated code returns via RET (X30/LR), with X20 holding the next
 * x86 RIP to translate. */
static int execute_block(translator_ctx_t *ctx, uint32_t *code) {
    x86_cpu_state_t *cpu = &ctx->cpu;

    /* The trampoline needs two pieces of info that survive across the BLR:
     * 1. cpu state pointer (to save registers back)
     * 2. code pointer (to call)
     *
     * We use x21 for cpu pointer and x22 for the code pointer.
     * We save callee-saved regs, load guest state, BLR, then save back.
     *
     * NOTE: We do NOT pass ret_rip as an asm output because the compiler
     * may allocate it to a callee-saved register (x19-x28) which our
     * manual restore would clobber. Instead, we store RIP to memory
     * via str x20, [x21, #128] and read cpu->rip in C afterwards. */

    __asm__ volatile (
        /* Save callee-saved registers on the host stack */
        "stp x29, x30, [sp, #-16]!\n"
        "stp x27, x28, [sp, #-16]!\n"
        "stp x25, x26, [sp, #-16]!\n"
        "stp x23, x24, [sp, #-16]!\n"
        "stp x21, x22, [sp, #-16]!\n"
        "stp x19, x20, [sp, #-16]!\n"

        /* Save cpu pointer and code pointer to callee-saved regs */
        "mov x21, %[cpu]\n"          /* x21 = cpu state (survives BLR) */
        "mov x22, %[code]\n"         /* x22 = code ptr (survives BLR) */

        /* Load x86 guest GPRs from cpu state struct.
         * struct layout: gpr[0]=RAX, gpr[1]=RCX, gpr[2]=RDX, gpr[3]=RBX,
         *                gpr[4]=RSP, gpr[5]=RBP, gpr[6]=RSI, gpr[7]=RDI,
         *                gpr[8..15]=R8..R15
         * ARM mapping: RAX→X0, RCX→X1, RDX→X2, RBX→X3,
         *              RSI→X4, RDI→X5, RSP→X6, RBP→X7,
         *              R8→X8 .. R15→X15 */
        "ldp x0, x1, [x21, #0]\n"    /* RAX, RCX */
        "ldp x2, x3, [x21, #16]\n"   /* RDX, RBX */
        "ldr x6, [x21, #32]\n"       /* RSP (gpr[4]) */
        "ldr x7, [x21, #40]\n"       /* RBP (gpr[5]) */
        "ldp x4, x5, [x21, #48]\n"   /* RSI (gpr[6]), RDI (gpr[7]) */
        "ldp x8, x9, [x21, #64]\n"   /* R8, R9 */
        "ldp x10, x11, [x21, #80]\n" /* R10, R11 */
        "ldp x12, x13, [x21, #96]\n" /* R12, R13 */
        "ldp x14, x15, [x21, #112]\n"/* R14, R15 */

        /* Load RIP into x20 */
        "ldr x20, [x21, #128]\n"     /* rip field (16 * 8 = 128) */

        /* Load lazy flags state */
        "ldr x19, [x21, #136]\n"     /* flags_op */
        "ldr x25, [x21, #144]\n"     /* flags_op1 */
        "ldr x26, [x21, #152]\n"     /* flags_op2 */
        "ldr x27, [x21, #160]\n"     /* flags_res */
        "ldr x28, [x21, #168]\n"     /* flags_size */

        /* Call translated code via x22 (saved code pointer) */
        "blr x22\n"

        /* After return: save guest GPRs back to cpu state.
         * x21 still has the cpu pointer (callee-saved). */
        "stp x0, x1, [x21, #0]\n"    /* RAX, RCX */
        "stp x2, x3, [x21, #16]\n"   /* RDX, RBX */
        "str x6, [x21, #32]\n"       /* RSP */
        "str x7, [x21, #40]\n"       /* RBP */
        "stp x4, x5, [x21, #48]\n"   /* RSI, RDI */
        "stp x8, x9, [x21, #64]\n"   /* R8, R9 */
        "stp x10, x11, [x21, #80]\n" /* R10, R11 */
        "stp x12, x13, [x21, #96]\n" /* R12, R13 */
        "stp x14, x15, [x21, #112]\n"/* R14, R15 */

        /* Save RIP (x20) and lazy flags back to memory */
        "str x20, [x21, #128]\n"     /* rip */
        "str x19, [x21, #136]\n"     /* flags_op */
        "str x25, [x21, #144]\n"     /* flags_op1 */
        "str x26, [x21, #152]\n"     /* flags_op2 */
        "str x27, [x21, #160]\n"     /* flags_res */
        "str x28, [x21, #168]\n"     /* flags_size */

        /* Restore callee-saved registers */
        "ldp x19, x20, [sp], #16\n"
        "ldp x21, x22, [sp], #16\n"
        "ldp x23, x24, [sp], #16\n"
        "ldp x25, x26, [sp], #16\n"
        "ldp x27, x28, [sp], #16\n"
        "ldp x29, x30, [sp], #16\n"

        : /* no outputs - RIP is stored to memory via str x20,[x21,#128] */
        : /* inputs */
          [cpu] "r" (cpu),
          [code] "r" (code)
        : /* clobbers - we manually save/restore callee-saved regs (x19-x28)
           * inside the asm block, so only declare volatile regs as clobbers */
          "memory",
          "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
          "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
          "x16", "x17"
    );

    /* RIP is already stored in cpu->rip by the asm block (str x20, [x21, #128]).
     * No need to copy from a register output — this avoids the issue where
     * the compiler allocates the output to a callee-saved register that
     * gets clobbered by our manual restore sequence. */

    return 0;
}

/* Translate one basic block starting at x86_addr.
 * Returns a pointer to the translated ARM64 code. */
uint32_t *translate_block(translator_ctx_t *ctx, uint64_t x86_addr) {
    /* Check cache first */
    cache_entry_t *cached = cache_lookup(&ctx->cache, x86_addr);
    if (cached) {
        ctx->stats.cache_hits++;
        cached->exec_count++;
        return cached->arm64_code;
    }
    ctx->stats.cache_misses++;

    /* Get host pointer for the x86 code */
    uint8_t *host_code = macho_guest_to_host(&ctx->binary, x86_addr);
    if (!host_code) {
        LOG_ERR("Cannot translate: guest address 0x%llx not mapped",
                (unsigned long long)x86_addr);
        return NULL;
    }

    /* Remember where we start emitting ARM64 code */
    uint32_t *block_start = jit_cursor(&ctx->jit);
    size_t code_start = ctx->jit.code_used;

    /* Enter writable mode for JIT buffer */
    jit_begin_write();

    /* Decode and translate instructions until we hit a block terminator */
    uint64_t current_addr = x86_addr;
    int instr_count = 0;
    bool block_ended = false;

    while (!block_ended && instr_count < MAX_BLOCK_SIZE) {
        x86_instr_t instr;
        uint8_t *instr_host = macho_guest_to_host(&ctx->binary, current_addr);
        if (!instr_host) {
            LOG_ERR("Guest address 0x%llx unmapped during block translation",
                    (unsigned long long)current_addr);
            break;
        }

        /* Calculate remaining bytes in the segment */
        size_t max_len = X86_MAX_INSTR_LEN;  /* Simplified; could check segment bounds */

        int consumed = x86_decode(instr_host, max_len, current_addr, &instr);
        if (consumed <= 0) {
            LOG_ERR("Decode failed at 0x%llx", (unsigned long long)current_addr);
            /* Emit breakpoint for debugging */
            emit_brk(&ctx->jit, 0xDEAD);
            break;
        }

        /* Trace decoded instruction if enabled */
        if (ctx->trace.trace_decode) {
            trace_x86_instr(instr.addr, instr.bytes, instr.length,
                           x86_format_instr(&instr));
        }

        /* Translate the instruction to ARM64 */
        int result = translate_instr_direct(ctx, &instr);
        if (result != 0) {
            LOG_WARN("Translation failed for instruction at 0x%llx: %s",
                     (unsigned long long)instr.addr, x86_format_instr(&instr));
            /* Set RIP past the failed instruction and return to dispatcher */
            emit_mov_imm64(&ctx->jit, ARM_RIP, current_addr + consumed);
            emit_ret(&ctx->jit, ARM_LR);
            break;
        }

        ctx->stats.instructions_translated++;
        instr_count++;
        current_addr += consumed;

        /* Check if this instruction ends the basic block */
        if (x86_is_block_terminator(&instr)) {
            block_ended = true;
        }
    }

    /* If we hit the max block size without a terminator, end the block */
    if (!block_ended) {
        emit_mov_imm64(&ctx->jit, ARM_RIP, current_addr);
        emit_ret(&ctx->jit, ARM_LR);
    }

    /* End writable mode and flush icache */
    size_t code_size = ctx->jit.code_used - code_start;
    jit_end_write(&ctx->jit, block_start, code_size);

    /* Cache the translated block */
    uint32_t x86_size = (uint32_t)(current_addr - x86_addr);
    cache_insert(&ctx->cache, x86_addr, block_start, (uint32_t)code_size, x86_size);

    ctx->stats.blocks_translated++;

    if (ctx->trace.trace_emit) {
        LOG_INFO("Translated block at x86:0x%llx (%d instrs, %zu ARM64 bytes)",
                 (unsigned long long)x86_addr, instr_count, code_size);
        /* Dump emitted ARM64 instructions */
        uint32_t *p = block_start;
        uint32_t *end = (uint32_t *)((uint8_t *)block_start + code_size);
        for (int i = 0; p < end; p++, i++) {
            fprintf(stderr, "  [%3d] %p: 0x%08X\n", i, (void *)p, *p);
        }
    }

    return block_start;
}

/* Initialize the translator context */
int translator_init(translator_ctx_t *ctx, const char *binary_path,
                    trace_flags_t trace) {
    memset(ctx, 0, sizeof(*ctx));
    ctx->trace = trace;
    g_trace = trace;

    /* Initialize opcode tables */
    x86_tables_init();

    /* Load Mach-O binary */
    LOG_INFO("Loading binary: %s", binary_path);
    if (macho_load(binary_path, &ctx->binary) != 0) {
        LOG_ERR("Failed to load binary: %s", binary_path);
        return -1;
    }

    if (ctx->trace.trace_decode) {
        macho_dump(&ctx->binary);
    }

    /* Map segments into guest memory */
    if (macho_map_segments(&ctx->binary) != 0) {
        LOG_ERR("Failed to map binary segments");
        macho_free(&ctx->binary);
        return -1;
    }

    /* Initialize JIT memory */
    if (jit_init(&ctx->jit, JIT_CODE_SIZE, GUEST_STACK_SIZE) != 0) {
        LOG_ERR("Failed to initialize JIT memory");
        macho_free(&ctx->binary);
        return -1;
    }

    /* Register mapped segments with JIT memory for address translation */
    for (int i = 0; i < ctx->binary.num_segments; i++) {
        mapped_segment_t *seg = &ctx->binary.segments[i];
        if (seg->host_addr) {
            jit_add_guest_region(&ctx->jit, seg->vmaddr, seg->vmsize,
                                 seg->host_addr,
                                 (seg->initprot & 2) != 0,  /* writable */
                                 seg->segname);
        }
    }

    /* Initialize translation cache */
    if (cache_init(&ctx->cache, CACHE_DEFAULT_CAP) != 0) {
        LOG_ERR("Failed to initialize translation cache");
        jit_free(&ctx->jit);
        macho_free(&ctx->binary);
        return -1;
    }

    /* Initialize CPU state */
    ctx->entry_point = ctx->binary.entry_point;
    cpu_state_init(&ctx->cpu, ctx->entry_point, ctx->jit.stack_top);

    LOG_INFO("Entry point: 0x%llx", (unsigned long long)ctx->entry_point);
    LOG_INFO("Guest stack top: 0x%llx", (unsigned long long)ctx->jit.stack_top);

    /* Install signal handlers */
    signal_handler_init(ctx);

    return 0;
}

/* Main execution loop */
int translator_run(translator_ctx_t *ctx) {
    LOG_INFO("Starting translation at RIP=0x%llx",
             (unsigned long long)ctx->cpu.rip);

    while (!ctx->guest_exited) {
        if (ctx->trace.trace_exec) {
            trace_exec(&ctx->cpu);
        }

        /* Translate the block at current RIP */
        uint32_t *code = translate_block(ctx, ctx->cpu.rip);
        if (!code) {
            LOG_ERR("Translation failed at RIP=0x%llx",
                    (unsigned long long)ctx->cpu.rip);
            return -1;
        }

        /* Execute the translated block */
        execute_block(ctx, code);

        /* Check if the guest executed an exit syscall */
        /* The exit syscall is detected by checking if RIP is 0 (set by our handler) */
        if (ctx->cpu.rip == 0 || ctx->guest_exited) {
            break;
        }
    }

    if (ctx->trace.trace_exec || ctx->trace.trace_decode) {
        translator_dump_stats(ctx);
    }

    return ctx->guest_exit_code;
}

/* Clean up */
void translator_destroy(translator_ctx_t *ctx) {
    signal_handler_cleanup();
    cache_free(&ctx->cache);
    jit_free(&ctx->jit);
    macho_free(&ctx->binary);
}

/* Print statistics */
void translator_dump_stats(const translator_ctx_t *ctx) {
    const translate_stats_t *s = &ctx->stats;
    fprintf(stderr, "\n=== Translation Statistics ===\n");
    fprintf(stderr, "Blocks translated:       %llu\n", (unsigned long long)s->blocks_translated);
    fprintf(stderr, "Instructions translated:  %llu\n", (unsigned long long)s->instructions_translated);
    fprintf(stderr, "Cache hits:              %llu\n", (unsigned long long)s->cache_hits);
    fprintf(stderr, "Cache misses:            %llu\n", (unsigned long long)s->cache_misses);
    fprintf(stderr, "Syscalls handled:        %llu\n", (unsigned long long)s->syscalls_handled);
    fprintf(stderr, "Unimplemented instrs:    %llu\n", (unsigned long long)s->unimplemented_count);
    if (s->cache_hits + s->cache_misses > 0) {
        fprintf(stderr, "Cache hit rate:          %.1f%%\n",
                100.0 * s->cache_hits / (s->cache_hits + s->cache_misses));
    }
    cache_dump_stats(&ctx->cache);
}
