/*
 * memory.h - JIT memory manager and guest memory mapping
 *
 * Manages MAP_JIT code buffers for emitting ARM64 code, and guest memory
 * regions for the x86_64 binary's address space.
 */

#ifndef MEMORY_H
#define MEMORY_H

#include "alt_rosetta.h"

/* Maximum guest memory regions */
#define MAX_GUEST_REGIONS 64

/* A region of guest memory (mapped segment or allocated area) */
typedef struct {
    uint64_t guest_addr;    /* Guest (x86) virtual address */
    uint64_t size;          /* Region size */
    uint8_t *host_addr;     /* Host (ARM64) mapping */
    bool     writable;
    bool     executable;
    char     name[32];      /* Debug name (e.g., "__TEXT") */
} guest_region_t;

/* JIT code buffer (MAP_JIT allocated) */
struct jit_memory {
    /* Code buffer */
    uint8_t    *code_base;      /* Base address of MAP_JIT region */
    size_t      code_capacity;  /* Total size of code buffer */
    size_t      code_used;      /* Bytes used so far */

    /* Guest memory regions */
    guest_region_t regions[MAX_GUEST_REGIONS];
    int            num_regions;

    /* Guest stack */
    uint8_t    *stack_base;     /* Bottom of guest stack (lowest address) */
    size_t      stack_size;     /* Total stack size */
    uint64_t    stack_top;      /* Top of stack (highest address, initial RSP) */
};

/* Initialize the JIT memory manager.
 * Allocates the code buffer with MAP_JIT and a guest stack.
 * Returns 0 on success, -1 on error. */
int jit_init(jit_memory_t *jit, size_t code_size, size_t stack_size);

/* Begin writing to the JIT code buffer (disable W^X protection).
 * Must be called before any emit_inst() or code modification. */
void jit_begin_write(void);

/* End writing to the JIT code buffer (re-enable W^X protection).
 * Also invalidates the instruction cache for the modified region. */
void jit_end_write(jit_memory_t *jit, void *start, size_t size);

/* Emit a single 32-bit ARM64 instruction into the code buffer.
 * Returns the address where the instruction was written. */
uint32_t *jit_emit(jit_memory_t *jit, uint32_t instruction);

/* Get the current write cursor as an instruction pointer. */
uint32_t *jit_cursor(jit_memory_t *jit);

/* Add a guest memory region for address translation. */
int jit_add_guest_region(jit_memory_t *jit, uint64_t guest_addr, uint64_t size,
                         uint8_t *host_addr, bool writable, const char *name);

/* Translate a guest address to a host pointer.
 * Returns NULL if the address is not in any mapped region. */
uint8_t *jit_guest_to_host(const jit_memory_t *jit, uint64_t guest_addr);

/* Translate a host pointer back to a guest address.
 * Returns 0 if not found. */
uint64_t jit_host_to_guest(const jit_memory_t *jit, const uint8_t *host_addr);

/* Free all JIT memory. */
void jit_free(jit_memory_t *jit);

#endif /* MEMORY_H */
