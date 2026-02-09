/*
 * signal_handler.h - Signal handling for the translator
 *
 * Installs signal handlers for SIGSEGV, SIGFPE, SIGBUS, SIGTRAP.
 * When a signal occurs in translated code, we:
 * 1. Map the ARM64 PC back to an x86 RIP via the translation cache
 * 2. Reconstruct the x86 CPU state from ARM64 registers
 * 3. If the guest has a handler, build a signal frame and call it
 * 4. Otherwise, report the fault and exit
 */

#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H

#include "alt_rosetta.h"

/* Install signal handlers for the translator.
 * Must be called after translator_init(). */
void signal_handler_init(translator_ctx_t *ctx);

/* Remove signal handlers (cleanup). */
void signal_handler_cleanup(void);

#endif /* SIGNAL_HANDLER_H */
