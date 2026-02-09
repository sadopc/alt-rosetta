/*
 * syscall.c - x86_64 to ARM64 syscall translation for macOS
 *
 * Translates x86_64 SYSCALL instructions by routing them through a C handler.
 * This is necessary because syscall arguments may contain guest virtual addresses
 * that need translation to host addresses before the kernel can use them.
 *
 * Calling conventions:
 *   x86_64:  number=RAX (0x2000000|n), args=RDI,RSI,RDX,R10,R8,R9
 *   ARM64:   number=X16,              args=X0,X1,X2,X3,X4,X5
 *
 * Instead of emitting SVC directly, we:
 * 1. Save guest registers to the cpu state struct (via X21)
 * 2. Call handle_syscall() in C which does address translation
 * 3. Load the result back from the cpu state
 */

#include "syscall.h"
#include "translate.h"  /* includes macho_loader.h and memory.h */
#include "debug.h"
#include <unistd.h>
#include <errno.h>

/*
 * Resolve a guest pointer to a host pointer.
 * Checks: Mach-O segments, JIT guest regions, guest stack (already host addr).
 */
static uint8_t *resolve_guest_ptr(translator_ctx_t *ctx, uint64_t guest_addr) {
    /* Check Mach-O mapped segments (code, data, cstrings) */
    uint8_t *host = macho_guest_to_host(&ctx->binary, guest_addr);
    if (host) return host;

    /* Check JIT guest regions */
    host = jit_guest_to_host(&ctx->jit, guest_addr);
    if (host) return host;

    /* Check if address falls within the mmap'd guest stack.
     * The guest stack uses host addresses directly (RSP = host addr). */
    if (ctx->jit.stack_base) {
        uint8_t *stack_lo = ctx->jit.stack_base;
        uint8_t *stack_hi = ctx->jit.stack_base + ctx->jit.stack_size;
        uint8_t *ptr = (uint8_t *)(uintptr_t)guest_addr;
        if (ptr >= stack_lo && ptr < stack_hi) {
            return ptr;
        }
    }

    return NULL;
}

/*
 * emit_syscall - Generate ARM64 code to route a SYSCALL through C handler.
 *
 * The generated code:
 * 1. Saves all guest GPRs (X0-X15) and RIP (X20) to the cpu state struct
 *    via X21 (which holds the ctx/cpu pointer from the trampoline).
 * 2. Sets up X0 = ctx pointer (X21) as argument to handle_syscall
 * 3. Loads the address of handle_syscall into a scratch register
 * 4. Calls handle_syscall via BLR
 * 5. Reloads guest GPRs from the cpu state (handle_syscall may modify them)
 *
 * X21 is callee-saved, so it survives the BLR to handle_syscall.
 */
void emit_syscall(jit_memory_t *jit, translator_ctx_t *ctx)
{
    (void)ctx;

    LOG_DBG("Emitting SYSCALL translation (C handler path)");

    /*
     * Step 1: Save all guest GPRs to cpu state struct via X21.
     * The struct layout: gpr[0]=RAX(X0), gpr[1]=RCX(X1), gpr[2]=RDX(X2),
     * gpr[3]=RBX(X3), gpr[4]=RSP(X6), gpr[5]=RBP(X7),
     * gpr[6]=RSI(X4), gpr[7]=RDI(X5), gpr[8..15]=R8(X8)..R15(X15)
     */
    emit_stp(jit, true, ARM_RAX, ARM_RCX, ARM_CTX, 0);    /* gpr[0], gpr[1] @ 0 */
    emit_stp(jit, true, ARM_RDX, ARM_RBX, ARM_CTX, 16);   /* gpr[2], gpr[3] @ 16 */
    emit_str_imm(jit, true, ARM_RSP, ARM_CTX, 32);         /* gpr[4] @ 32 */
    emit_str_imm(jit, true, ARM_RBP, ARM_CTX, 40);         /* gpr[5] @ 40 */
    emit_stp(jit, true, ARM_RSI, ARM_RDI, ARM_CTX, 48);   /* gpr[6], gpr[7] @ 48 */
    emit_stp(jit, true, ARM_R8, ARM_R9, ARM_CTX, 64);     /* gpr[8], gpr[9] @ 64 */
    emit_stp(jit, true, ARM_R10, ARM_R11, ARM_CTX, 80);   /* gpr[10], gpr[11] @ 80 */
    emit_stp(jit, true, ARM_R12, ARM_R13, ARM_CTX, 96);   /* gpr[12], gpr[13] @ 96 */
    emit_stp(jit, true, ARM_R14, ARM_R15, ARM_CTX, 112);  /* gpr[14], gpr[15] @ 112 */
    emit_str_imm(jit, true, ARM_RIP, ARM_CTX, 128);        /* rip @ 128 */

    /*
     * Step 2: Save LR (X30) and FP (X29) before calling handle_syscall.
     * BLR clobbers LR, and we need the original LR to return to the
     * trampoline in execute_block after we're done.
     * STP X29, X30, [SP, #-16]!  (pre-index)
     */
    emit_raw(jit, 0xA9BF7BFD);

    /*
     * Step 3: Call handle_syscall(ctx).
     * X0 = ctx pointer (same as cpu pointer since cpu is first field)
     * Load the function address into X16 (scratch), then BLR.
     */
    emit_mov_reg(jit, true, 0, ARM_CTX);  /* MOV X0, X21 (arg0 = ctx) */
    emit_mov_imm64(jit, ARM_SCRATCH0, (uint64_t)(uintptr_t)&handle_syscall);
    emit_blr(jit, ARM_SCRATCH0);           /* BLR X16 → handle_syscall(ctx) */

    /*
     * Step 4: Restore LR and FP.
     * LDP X29, X30, [SP], #16  (post-index)
     */
    emit_raw(jit, 0xA8C17BFD);

    /*
     * Step 5: Reload guest GPRs from cpu state.
     * handle_syscall stored the result in ctx->cpu.gpr[RAX], so loading
     * everything back gives us the updated state.
     */
    emit_ldp(jit, true, ARM_RAX, ARM_RCX, ARM_CTX, 0);    /* gpr[0], gpr[1] */
    emit_ldp(jit, true, ARM_RDX, ARM_RBX, ARM_CTX, 16);   /* gpr[2], gpr[3] */
    emit_ldr_imm(jit, true, ARM_RSP, ARM_CTX, 32);         /* gpr[4] */
    emit_ldr_imm(jit, true, ARM_RBP, ARM_CTX, 40);         /* gpr[5] */
    emit_ldp(jit, true, ARM_RSI, ARM_RDI, ARM_CTX, 48);   /* gpr[6], gpr[7] */
    emit_ldp(jit, true, ARM_R8, ARM_R9, ARM_CTX, 64);     /* gpr[8], gpr[9] */
    emit_ldp(jit, true, ARM_R10, ARM_R11, ARM_CTX, 80);   /* gpr[10], gpr[11] */
    emit_ldp(jit, true, ARM_R12, ARM_R13, ARM_CTX, 96);   /* gpr[12], gpr[13] */
    emit_ldp(jit, true, ARM_R14, ARM_R15, ARM_CTX, 112);  /* gpr[14], gpr[15] */
    emit_ldr_imm(jit, true, ARM_RIP, ARM_CTX, 128);        /* rip */
}

/*
 * handle_syscall - Runtime syscall handler (called from JIT code).
 *
 * Reads syscall number and arguments from the cpu state,
 * translates guest pointers to host pointers where needed,
 * executes the real syscall, and stores the result back.
 */
int64_t handle_syscall(translator_ctx_t *ctx)
{
    uint64_t syscall_num = ctx->cpu.gpr[X86_RAX] & SYSCALL_NUMBER_MASK;
    int64_t result = -1;

    LOG_DBG("handle_syscall: num=%llu rdi=0x%llx rsi=0x%llx rdx=0x%llx",
            (unsigned long long)syscall_num,
            (unsigned long long)ctx->cpu.gpr[X86_RDI],
            (unsigned long long)ctx->cpu.gpr[X86_RSI],
            (unsigned long long)ctx->cpu.gpr[X86_RDX]);

    ctx->stats.syscalls_handled++;

    switch (syscall_num) {
    case SYS_exit: {
        int exit_code = (int)ctx->cpu.gpr[X86_RDI];
        ctx->guest_exited = true;
        ctx->guest_exit_code = exit_code;
        LOG_INFO("Guest exit with code %d", exit_code);
        /* Set RIP to 0 to signal exit to the dispatch loop */
        ctx->cpu.rip = 0;
        result = 0;
        break;
    }

    case SYS_write: {
        int fd = (int)ctx->cpu.gpr[X86_RDI];
        uint64_t guest_buf = ctx->cpu.gpr[X86_RSI];
        size_t count = (size_t)ctx->cpu.gpr[X86_RDX];

        /* Translate guest buffer address to host address */
        uint8_t *host_buf = resolve_guest_ptr(ctx, guest_buf);
        if (!host_buf) {
            LOG_ERR("write: guest buffer 0x%llx not mapped",
                    (unsigned long long)guest_buf);
            result = -1;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)-EFAULT;
            return result;
        }

        LOG_DBG("write(fd=%d, buf=0x%llx→%p, count=%zu)",
                fd, (unsigned long long)guest_buf, (void *)host_buf, count);

        ssize_t written = write(fd, host_buf, count);
        if (written < 0) {
            result = -errno;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)result;
        } else {
            result = written;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)written;
        }
        break;
    }

    case SYS_read: {
        int fd = (int)ctx->cpu.gpr[X86_RDI];
        uint64_t guest_buf = ctx->cpu.gpr[X86_RSI];
        size_t count = (size_t)ctx->cpu.gpr[X86_RDX];

        uint8_t *host_buf = resolve_guest_ptr(ctx, guest_buf);
        if (!host_buf) {
            LOG_ERR("read: guest buffer 0x%llx not mapped",
                    (unsigned long long)guest_buf);
            result = -1;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)-EFAULT;
            return result;
        }

        ssize_t bytes_read = read(fd, host_buf, count);
        if (bytes_read < 0) {
            result = -errno;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)result;
        } else {
            result = bytes_read;
            ctx->cpu.gpr[X86_RAX] = (uint64_t)bytes_read;
        }
        break;
    }

    default:
        LOG_WARN("Unhandled syscall %llu", (unsigned long long)syscall_num);
        ctx->cpu.gpr[X86_RAX] = (uint64_t)-ENOSYS;
        result = -ENOSYS;
        break;
    }

    return result;
}
