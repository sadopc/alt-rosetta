/*
 * translate.h - Translation engine (orchestrator)
 *
 * Ties together the decoder, IR, emitter, cache, and memory manager
 * into a complete binary translation pipeline.
 */

#ifndef TRANSLATE_H
#define TRANSLATE_H

#include "alt_rosetta.h"
#include "cpu_state.h"
#include "memory.h"
#include "cache.h"
#include "macho_loader.h"

/* Translation statistics */
typedef struct {
    uint64_t blocks_translated;
    uint64_t instructions_translated;
    uint64_t cache_hits;
    uint64_t cache_misses;
    uint64_t syscalls_handled;
    uint64_t unimplemented_count;
} translate_stats_t;

/* Main translator context - holds everything needed for translation and execution */
struct translator_ctx {
    /* Guest CPU state */
    x86_cpu_state_t cpu;

    /* Translation cache */
    trans_cache_t cache;

    /* JIT memory manager */
    jit_memory_t jit;

    /* Loaded binary */
    macho_binary_t binary;

    /* Entry point (guest address) */
    uint64_t entry_point;

    /* Debug/trace flags */
    trace_flags_t trace;

    /* Statistics */
    translate_stats_t stats;

    /* Whether the guest has exited */
    bool guest_exited;
    int  guest_exit_code;

    /* Use IR-based translation (Phase 6+) or direct (Phase 4-5) */
    bool use_ir;
};

/* Initialize the translator with a loaded binary.
 * Sets up memory, cache, CPU state, etc.
 * Returns 0 on success, -1 on error. */
int translator_init(translator_ctx_t *ctx, const char *binary_path,
                    trace_flags_t trace);

/* Translate one basic block starting at the current RIP.
 * Returns a pointer to the translated ARM64 code, or NULL on error. */
uint32_t *translate_block(translator_ctx_t *ctx, uint64_t x86_addr);

/* Main execution loop: translate and execute blocks until the guest exits.
 * Returns the guest's exit code. */
int translator_run(translator_ctx_t *ctx);

/* Clean up all translator resources. */
void translator_destroy(translator_ctx_t *ctx);

/* Print translation statistics. */
void translator_dump_stats(const translator_ctx_t *ctx);

/* Translate a single x86 instruction directly to ARM64 (Phase 4-5 path).
 * Returns 0 on success, -1 if unhandled. */
int translate_instr_direct(translator_ctx_t *ctx, const x86_instr_t *instr);

#endif /* TRANSLATE_H */
