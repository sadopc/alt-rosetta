/*
 * memory.c - JIT memory manager and guest memory mapping
 *
 * Manages MAP_JIT code buffers for emitting ARM64 code on macOS/ARM64,
 * and guest memory regions for the x86_64 binary's address space.
 */

#include "memory.h"
#include <sys/mman.h>
#include <pthread.h>
#include <libkern/OSCacheControl.h>

int jit_init(jit_memory_t *jit, size_t code_size, size_t stack_size) {
    memset(jit, 0, sizeof(*jit));

    /* Allocate JIT code buffer with MAP_JIT for W^X support */
    jit->code_base = (uint8_t *)mmap(NULL, code_size,
                                      PROT_READ | PROT_WRITE | PROT_EXEC,
                                      MAP_PRIVATE | MAP_ANON | MAP_JIT,
                                      -1, 0);
    if (jit->code_base == MAP_FAILED) {
        perror("mmap MAP_JIT code buffer");
        return -1;
    }
    jit->code_capacity = code_size;
    jit->code_used = 0;

    /* Allocate guest stack */
    jit->stack_base = (uint8_t *)mmap(NULL, stack_size,
                                       PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANON,
                                       -1, 0);
    if (jit->stack_base == MAP_FAILED) {
        perror("mmap guest stack");
        munmap(jit->code_base, code_size);
        jit->code_base = NULL;
        return -1;
    }
    jit->stack_size = stack_size;
    /* Stack grows downward: top is highest address, aligned to 16 bytes */
    jit->stack_top = (uint64_t)(jit->stack_base + stack_size) & ~(uint64_t)0xF;

    jit->num_regions = 0;

    return 0;
}

void jit_begin_write(void) {
    pthread_jit_write_protect_np(0);
}

void jit_end_write(jit_memory_t *jit, void *start, size_t size) {
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(start, size);
    (void)jit;
}

uint32_t *jit_emit(jit_memory_t *jit, uint32_t instruction) {
    uint32_t *addr = (uint32_t *)(jit->code_base + jit->code_used);
    *addr = instruction;
    jit->code_used += 4;
    return addr;
}

uint32_t *jit_cursor(jit_memory_t *jit) {
    return (uint32_t *)(jit->code_base + jit->code_used);
}

int jit_add_guest_region(jit_memory_t *jit, uint64_t guest_addr, uint64_t size,
                         uint8_t *host_addr, bool writable, const char *name) {
    if (jit->num_regions >= MAX_GUEST_REGIONS) {
        fprintf(stderr, "Too many guest regions (max %d)\n", MAX_GUEST_REGIONS);
        return -1;
    }

    guest_region_t *r = &jit->regions[jit->num_regions];
    r->guest_addr = guest_addr;
    r->size = size;
    r->host_addr = host_addr;
    r->writable = writable;
    r->executable = !writable;
    if (name) {
        strncpy(r->name, name, sizeof(r->name) - 1);
        r->name[sizeof(r->name) - 1] = '\0';
    } else {
        r->name[0] = '\0';
    }

    jit->num_regions++;
    return 0;
}

uint8_t *jit_guest_to_host(const jit_memory_t *jit, uint64_t guest_addr) {
    for (int i = 0; i < jit->num_regions; i++) {
        const guest_region_t *r = &jit->regions[i];
        if (guest_addr >= r->guest_addr && guest_addr < r->guest_addr + r->size) {
            uint64_t offset = guest_addr - r->guest_addr;
            return r->host_addr + offset;
        }
    }
    return NULL;
}

uint64_t jit_host_to_guest(const jit_memory_t *jit, const uint8_t *host_addr) {
    for (int i = 0; i < jit->num_regions; i++) {
        const guest_region_t *r = &jit->regions[i];
        if (host_addr >= r->host_addr && host_addr < r->host_addr + r->size) {
            uint64_t offset = (uint64_t)(host_addr - r->host_addr);
            return r->guest_addr + offset;
        }
    }
    return 0;
}

void jit_free(jit_memory_t *jit) {
    if (jit->code_base && jit->code_base != MAP_FAILED) {
        munmap(jit->code_base, jit->code_capacity);
        jit->code_base = NULL;
    }
    if (jit->stack_base && jit->stack_base != MAP_FAILED) {
        munmap(jit->stack_base, jit->stack_size);
        jit->stack_base = NULL;
    }
    jit->code_used = 0;
    jit->code_capacity = 0;
    jit->stack_size = 0;
    jit->stack_top = 0;
    jit->num_regions = 0;
}
