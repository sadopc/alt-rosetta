/*
 * syscall.h - x86_64 → ARM64 syscall translation for macOS
 *
 * macOS uses the same syscall numbers on both architectures, but the calling
 * conventions differ:
 *
 *   x86_64:  number in RAX (with 0x2000000 class prefix)
 *            args in RDI, RSI, RDX, R10, R8, R9
 *            result in RAX (CF=1 on error)
 *
 *   ARM64:   number in X16 (no class prefix)
 *            args in X0, X1, X2, X3, X4, X5
 *            result in X0 (carry flag on error)
 *            SVC #0x80
 *
 * We strip the class prefix, remap registers, emit SVC, then remap the result.
 */

#ifndef SYSCALL_H
#define SYSCALL_H

#include "alt_rosetta.h"
#include "arm64_emit.h"

/* macOS syscall class prefix mask */
#define SYSCALL_CLASS_MASK   0xFF000000
#define SYSCALL_CLASS_UNIX   0x02000000
#define SYSCALL_NUMBER_MASK  0x00FFFFFF

/* Common macOS syscall numbers (without class prefix) */
#define SYS_exit        1
#define SYS_fork        2
#define SYS_read        3
#define SYS_write       4
#define SYS_open        5
#define SYS_close       6
#define SYS_mmap        197
#define SYS_munmap      73
#define SYS_mprotect    74
#define SYS_brk         12

/* Emit ARM64 code for an x86 SYSCALL instruction.
 *
 * This generates code that:
 * 1. Reads the syscall number from X0 (mapped from RAX)
 * 2. Strips the 0x2000000 class prefix
 * 3. Remaps arguments from x86 convention to ARM64 convention
 * 4. Emits SVC #0x80
 * 5. Remaps the result back to X0 (RAX)
 *
 * Special handling for exit() syscall: instead of SVC, we call back
 * to the translator to cleanly shut down. */
void emit_syscall(jit_memory_t *jit, translator_ctx_t *ctx);

/* Handle a syscall at runtime (fallback for complex syscalls).
 * Called from generated code via BLR to this function.
 * Returns the syscall result. */
int64_t handle_syscall(translator_ctx_t *ctx);

#endif /* SYSCALL_H */
