/*
 * cache.c - Translation cache
 *
 * Hash table mapping x86_64 guest addresses to translated ARM64 code pointers.
 * Uses FNV-1a hash with linear probing for collision resolution.
 */

#include "cache.h"

/* FNV-1a constants for 64-bit */
#define FNV_OFFSET_BASIS 0xCBF29CE484222325ULL
#define FNV_PRIME        0x100000001B3ULL

static uint32_t cache_hash(uint64_t addr, uint32_t mask) {
    uint64_t h = FNV_OFFSET_BASIS;
    for (int i = 0; i < 8; i++) {
        h ^= (addr >> (i * 8)) & 0xFF;
        h *= FNV_PRIME;
    }
    return (uint32_t)(h & mask);
}

int cache_init(trans_cache_t *cache, uint32_t capacity) {
    cache->entries = (cache_entry_t *)calloc(capacity, sizeof(cache_entry_t));
    if (!cache->entries) {
        return -1;
    }
    cache->capacity = capacity;
    cache->count = 0;
    cache->mask = capacity - 1;
    return 0;
}

cache_entry_t *cache_lookup(trans_cache_t *cache, uint64_t x86_addr) {
    uint32_t idx = cache_hash(x86_addr, cache->mask);

    for (uint32_t i = 0; i < cache->capacity; i++) {
        uint32_t slot = (idx + i) & cache->mask;
        cache_entry_t *e = &cache->entries[slot];

        if (!e->valid && e->x86_addr == 0) {
            /* Empty slot, entry not found */
            return NULL;
        }
        if (e->valid && e->x86_addr == x86_addr) {
            e->exec_count++;
            return e;
        }
    }
    return NULL;
}

cache_entry_t *cache_insert(trans_cache_t *cache, uint64_t x86_addr,
                             uint32_t *arm64_code, uint32_t arm64_size,
                             uint32_t x86_size) {
    if (cache->count >= cache->capacity * 3 / 4) {
        /* Load factor too high */
        return NULL;
    }

    uint32_t idx = cache_hash(x86_addr, cache->mask);

    for (uint32_t i = 0; i < cache->capacity; i++) {
        uint32_t slot = (idx + i) & cache->mask;
        cache_entry_t *e = &cache->entries[slot];

        if (!e->valid) {
            e->x86_addr = x86_addr;
            e->arm64_code = arm64_code;
            e->arm64_size = arm64_size;
            e->x86_size = x86_size;
            e->exec_count = 0;
            e->valid = true;
            cache->count++;
            return e;
        }
        if (e->x86_addr == x86_addr) {
            /* Update existing entry */
            e->arm64_code = arm64_code;
            e->arm64_size = arm64_size;
            e->x86_size = x86_size;
            e->valid = true;
            return e;
        }
    }
    return NULL;
}

void cache_invalidate(trans_cache_t *cache, uint64_t x86_addr) {
    uint32_t idx = cache_hash(x86_addr, cache->mask);

    for (uint32_t i = 0; i < cache->capacity; i++) {
        uint32_t slot = (idx + i) & cache->mask;
        cache_entry_t *e = &cache->entries[slot];

        if (!e->valid && e->x86_addr == 0) {
            return;
        }
        if (e->valid && e->x86_addr == x86_addr) {
            e->valid = false;
            cache->count--;
            return;
        }
    }
}

void cache_clear(trans_cache_t *cache) {
    memset(cache->entries, 0, cache->capacity * sizeof(cache_entry_t));
    cache->count = 0;
}

void cache_free(trans_cache_t *cache) {
    free(cache->entries);
    cache->entries = NULL;
    cache->capacity = 0;
    cache->count = 0;
    cache->mask = 0;
}

void cache_dump_stats(const trans_cache_t *cache) {
    uint64_t total_execs = 0;
    uint32_t valid_count = 0;

    for (uint32_t i = 0; i < cache->capacity; i++) {
        if (cache->entries[i].valid) {
            valid_count++;
            total_execs += cache->entries[i].exec_count;
        }
    }

    printf("Translation cache stats:\n");
    printf("  Capacity:    %u\n", cache->capacity);
    printf("  Used:        %u (%.1f%%)\n", valid_count,
           cache->capacity > 0 ? (100.0 * valid_count / cache->capacity) : 0.0);
    printf("  Total execs: %llu\n", (unsigned long long)total_execs);
    if (valid_count > 0) {
        printf("  Avg execs:   %.1f\n", (double)total_execs / valid_count);
    }
}
