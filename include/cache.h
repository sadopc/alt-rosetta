/*
 * cache.h - Translation cache
 *
 * Hash table mapping x86_64 guest addresses to translated ARM64 code pointers.
 * Used to avoid re-translating previously seen basic blocks.
 */

#ifndef CACHE_H
#define CACHE_H

#include "alt_rosetta.h"

/* A single cache entry */
typedef struct {
    uint64_t    x86_addr;       /* Guest x86 address (0 = empty slot) */
    uint32_t   *arm64_code;     /* Pointer to translated ARM64 code */
    uint32_t    arm64_size;     /* Size of translated code in bytes */
    uint32_t    x86_size;       /* Size of x86 basic block in bytes */
    uint64_t    exec_count;     /* Number of times this block was executed */
    bool        valid;          /* Entry is valid */
} cache_entry_t;

/* Translation cache */
struct trans_cache {
    cache_entry_t  *entries;
    uint32_t        capacity;   /* Total slots (power of 2) */
    uint32_t        count;      /* Used slots */
    uint32_t        mask;       /* capacity - 1, for fast modulo */
};

/* Initialize the translation cache.
 * capacity must be a power of 2. */
int cache_init(trans_cache_t *cache, uint32_t capacity);

/* Look up a translated block by x86 address.
 * Returns the cache entry or NULL if not found. */
cache_entry_t *cache_lookup(trans_cache_t *cache, uint64_t x86_addr);

/* Insert a translated block into the cache.
 * Returns the cache entry, or NULL if the cache is full. */
cache_entry_t *cache_insert(trans_cache_t *cache, uint64_t x86_addr,
                            uint32_t *arm64_code, uint32_t arm64_size,
                            uint32_t x86_size);

/* Remove an entry from the cache. */
void cache_invalidate(trans_cache_t *cache, uint64_t x86_addr);

/* Clear all entries. */
void cache_clear(trans_cache_t *cache);

/* Free the cache. */
void cache_free(trans_cache_t *cache);

/* Print cache statistics. */
void cache_dump_stats(const trans_cache_t *cache);

#endif /* CACHE_H */
