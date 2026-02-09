/*
 * dump_macho.c - Standalone Mach-O binary dumper
 *
 * Usage: dump_macho <mach-o-binary>
 *
 * Parses and prints the Mach-O header, load commands, segments, and sections
 * of an x86_64 binary. Useful for understanding binary structure and
 * verifying the Mach-O loader.
 */

#include "alt_rosetta.h"
#include "macho_loader.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mach-o-binary>\n", argv[0]);
        return 1;
    }

    macho_binary_t binary;
    memset(&binary, 0, sizeof(binary));

    if (macho_load(argv[1], &binary) != 0) {
        fprintf(stderr, "Failed to parse Mach-O binary: %s\n", argv[1]);
        return 1;
    }

    printf("=== Mach-O Binary: %s ===\n\n", argv[1]);
    macho_dump(&binary);

    macho_free(&binary);
    return 0;
}
