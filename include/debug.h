/*
 * debug.h - Trace and logging utilities
 */

#ifndef DEBUG_H
#define DEBUG_H

#include "alt_rosetta.h"

/* Log levels */
typedef enum {
    LOG_ERROR = 0,
    LOG_WARN  = 1,
    LOG_INFO  = 2,
    LOG_DEBUG = 3,
    LOG_TRACE = 4,
} log_level_t;

/* Global trace flags (set from command line) */
extern trace_flags_t g_trace;

/* Global log level */
extern log_level_t g_log_level;

/* Logging macros - use __VA_OPT__ (C23) to avoid GNU extension warnings */
#define LOG_ERR(...)   log_msg(LOG_ERROR, __VA_ARGS__)
#define LOG_WARN(...)  log_msg(LOG_WARN,  __VA_ARGS__)
#define LOG_INFO(...)  log_msg(LOG_INFO,  __VA_ARGS__)
#define LOG_DBG(...)   log_msg(LOG_DEBUG, __VA_ARGS__)

/* Core logging function */
void log_msg(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Trace: decoded x86 instruction */
void trace_x86_instr(uint64_t addr, const uint8_t *bytes, size_t len, const char *mnemonic);

/* Trace: emitted ARM64 instruction */
void trace_arm64_instr(uint32_t *addr, uint32_t inst, const char *desc);

/* Trace: execution (RIP and register summary) */
void trace_exec(const x86_cpu_state_t *state);

/* Hexdump utility */
void hexdump(const void *data, size_t size, uint64_t base_addr);

/* Format an x86 instruction as a string for display */
const char *x86_mnemonic_name(int opcode_type);

#endif /* DEBUG_H */
