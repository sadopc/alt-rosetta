/*
 * macho_loader.h - Mach-O binary parser for x86_64 executables
 *
 * Parses Mach-O headers, load commands, and maps segments into guest memory.
 */

#ifndef MACHO_LOADER_H
#define MACHO_LOADER_H

#include "alt_rosetta.h"
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

/* Maximum segments we track */
#define MAX_SEGMENTS 32

/* Maximum imported dylibs */
#define MAX_DYLIBS 64

/* A mapped segment in guest memory */
typedef struct {
    char        segname[16];
    uint64_t    vmaddr;         /* Guest virtual address */
    uint64_t    vmsize;
    uint64_t    fileoff;
    uint64_t    filesize;
    uint32_t    maxprot;
    uint32_t    initprot;
    uint8_t    *host_addr;      /* Where it's mapped in our address space */
} mapped_segment_t;

/* Parsed Mach-O binary */
struct macho_binary {
    /* Raw file data */
    uint8_t    *file_data;
    size_t      file_size;

    /* Header info */
    uint32_t    magic;
    uint32_t    cputype;
    uint32_t    cpusubtype;
    uint32_t    filetype;
    uint32_t    ncmds;
    uint32_t    sizeofcmds;
    uint32_t    flags;

    /* Entry point (guest address) */
    uint64_t    entry_point;

    /* Segments */
    mapped_segment_t segments[MAX_SEGMENTS];
    int         num_segments;

    /* __TEXT segment base (used for entry point calculation) */
    uint64_t    text_vmaddr;

    /* Imported dylibs */
    char       *dylibs[MAX_DYLIBS];
    int         num_dylibs;

    /* Symbol table (if present) */
    struct nlist_64 *symtab;
    uint32_t    nsyms;
    char       *strtab;
    uint32_t    strsize;
};

/* Load and parse a Mach-O x86_64 binary from a file path.
 * Returns 0 on success, -1 on error. */
int macho_load(const char *path, macho_binary_t *binary);

/* Map all segments of the binary into guest memory.
 * Uses the provided jit_memory for allocation tracking.
 * Returns 0 on success, -1 on error. */
int macho_map_segments(macho_binary_t *binary);

/* Look up a symbol by name. Returns guest address or 0 if not found. */
uint64_t macho_lookup_symbol(const macho_binary_t *binary, const char *name);

/* Translate a guest address to a host pointer.
 * Returns NULL if the address is not in any mapped segment. */
uint8_t *macho_guest_to_host(const macho_binary_t *binary, uint64_t guest_addr);

/* Free all resources associated with the binary. */
void macho_free(macho_binary_t *binary);

/* Print parsed Mach-O info (for debugging / dump_macho tool) */
void macho_dump(const macho_binary_t *binary);

#endif /* MACHO_LOADER_H */
