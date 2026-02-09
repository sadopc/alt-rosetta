/*
 * main.c - Alternative Rosetta entry point
 *
 * Usage: alt-rosetta [options] <x86_64-binary> [args...]
 *
 * Options:
 *   --trace-decode  Print each decoded x86 instruction
 *   --trace-ir      Print IR after translation
 *   --trace-emit    Print each emitted ARM64 instruction
 *   --trace-exec    Print execution trace (RIP + registers)
 *   --help          Show usage information
 *   --version       Show version
 */

#include "alt_rosetta.h"
#include "translate.h"
#include "debug.h"

#include <stdio.h>
#include <string.h>

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Alternative Rosetta v" ALT_ROSETTA_VERSION_STRING "\n"
        "Educational x86_64 → ARM64 dynamic binary translator for macOS Apple Silicon\n"
        "\n"
        "Usage: %s [options] <x86_64-binary> [args...]\n"
        "\n"
        "Options:\n"
        "  --trace-decode  Print each decoded x86 instruction\n"
        "  --trace-ir      Print IR after translation\n"
        "  --trace-emit    Print each emitted ARM64 instruction\n"
        "  --trace-exec    Print execution trace (RIP + registers)\n"
        "  --trace-all     Enable all trace output\n"
        "  --help          Show this help message\n"
        "  --version       Show version\n",
        prog);
}

static void print_version(void) {
    printf("alt-rosetta %s\n", ALT_ROSETTA_VERSION_STRING);
}

int main(int argc, char *argv[]) {
    trace_flags_t trace = {0};
    const char *binary_path = NULL;
    (void)argc; /* args after binary_path are for the guest */

    /* Parse arguments */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--trace-decode") == 0) {
            trace.trace_decode = true;
        } else if (strcmp(argv[i], "--trace-ir") == 0) {
            trace.trace_ir = true;
        } else if (strcmp(argv[i], "--trace-emit") == 0) {
            trace.trace_emit = true;
        } else if (strcmp(argv[i], "--trace-exec") == 0) {
            trace.trace_exec = true;
        } else if (strcmp(argv[i], "--trace-all") == 0) {
            trace.trace_decode = true;
            trace.trace_ir = true;
            trace.trace_emit = true;
            trace.trace_exec = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (argv[i][0] == '-') {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        } else {
            /* First non-option argument is the binary path */
            binary_path = argv[i];
            break;
        }
    }

    if (!binary_path) {
        fprintf(stderr, "Error: no binary specified\n\n");
        print_usage(argv[0]);
        return 1;
    }

    /* Set global log level based on trace flags */
    if (trace.trace_decode || trace.trace_ir || trace.trace_emit || trace.trace_exec) {
        g_log_level = LOG_TRACE;
    } else {
        g_log_level = LOG_WARN;
    }

    LOG_INFO("Alternative Rosetta v%s", ALT_ROSETTA_VERSION_STRING);
    LOG_INFO("Binary: %s", binary_path);

    /* Initialize translator */
    translator_ctx_t ctx;
    int result = translator_init(&ctx, binary_path, trace);
    if (result != 0) {
        LOG_ERR("Failed to initialize translator");
        return 1;
    }

    /* Run the binary */
    int exit_code = translator_run(&ctx);

    /* Clean up */
    translator_destroy(&ctx);

    return exit_code;
}
