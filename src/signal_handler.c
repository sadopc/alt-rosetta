/*
 * signal_handler.c - Signal handling for the translator
 *
 * Installs handlers for SIGSEGV, SIGFPE, SIGBUS, SIGTRAP to catch faults
 * in translated code and report them with x86 context information.
 */

#include "signal_handler.h"
#include "translate.h"
#include "cache.h"
#include "debug.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Global translator context for signal handler access */
static translator_ctx_t *g_ctx = NULL;

/* Signal handler for faults in translated code */
static void fault_handler(int sig, siginfo_t *info, void *ucontext) {
    (void)ucontext;

    const char *sig_name;
    switch (sig) {
        case SIGSEGV: sig_name = "SIGSEGV"; break;
        case SIGFPE:  sig_name = "SIGFPE";  break;
        case SIGBUS:  sig_name = "SIGBUS";  break;
        case SIGTRAP: sig_name = "SIGTRAP"; break;
        default:      sig_name = "UNKNOWN"; break;
    }

    fprintf(stderr, "\n=== FAULT: %s ===\n", sig_name);
    fprintf(stderr, "Faulting address: %p\n", info->si_addr);

    if (g_ctx) {
        fprintf(stderr, "Guest RIP: 0x%llx\n",
                (unsigned long long)g_ctx->cpu.rip);
        cpu_state_dump(&g_ctx->cpu);

        /* Try to look up the x86 address from the translation cache */
        /* The ARM64 PC at fault time would need to be mapped back,
         * but we can at least show the last known x86 RIP */
    }

    fprintf(stderr, "\nTranslator terminated due to unhandled signal.\n");

    if (g_ctx && (g_ctx->trace.trace_decode || g_ctx->trace.trace_exec)) {
        translator_dump_stats(g_ctx);
    }

    /* Re-raise with default handler to get core dump */
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Install signal handlers */
void signal_handler_init(translator_ctx_t *ctx) {
    g_ctx = ctx;

    struct sigaction sa;
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGFPE, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    sigaction(SIGTRAP, &sa, NULL);

    LOG_DBG("Signal handlers installed");
}

/* Remove signal handlers */
void signal_handler_cleanup(void) {
    signal(SIGSEGV, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGTRAP, SIG_DFL);
    g_ctx = NULL;
}
