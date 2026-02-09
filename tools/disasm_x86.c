/*
 * disasm_x86.c - Standalone x86_64 disassembler
 *
 * Usage: disasm_x86 <x86_64-binary>
 *
 * Reads a Mach-O binary and disassembles its __TEXT,__text section
 * using the x86 decoder. Useful for validating the decoder against
 * llvm-objdump -d output.
 */

#include "alt_rosetta.h"
#include "macho_loader.h"
#include "x86_decode.h"
#include "x86_tables.h"
#include "debug.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <x86_64-binary>\n", argv[0]);
        return 1;
    }

    /* Initialize opcode tables */
    x86_tables_init();

    /* Load binary */
    macho_binary_t binary;
    memset(&binary, 0, sizeof(binary));

    if (macho_load(argv[1], &binary) != 0) {
        fprintf(stderr, "Failed to parse Mach-O binary: %s\n", argv[1]);
        return 1;
    }

    if (macho_map_segments(&binary) != 0) {
        fprintf(stderr, "Failed to map segments\n");
        macho_free(&binary);
        return 1;
    }

    /* Find __TEXT segment */
    uint64_t text_addr = 0;
    uint64_t text_size = 0;
    uint8_t *text_host = NULL;

    for (int i = 0; i < binary.num_segments; i++) {
        if (strcmp(binary.segments[i].segname, "__TEXT") == 0) {
            text_addr = binary.segments[i].vmaddr;
            text_size = binary.segments[i].vmsize;
            text_host = binary.segments[i].host_addr;
            break;
        }
    }

    if (!text_host) {
        fprintf(stderr, "No __TEXT segment found\n");
        macho_free(&binary);
        return 1;
    }

    printf("Disassembly of __TEXT (0x%llx - 0x%llx):\n\n",
           (unsigned long long)text_addr,
           (unsigned long long)(text_addr + text_size));

    /* Decode and print instructions */
    uint64_t offset = 0;
    while (offset < text_size) {
        x86_instr_t instr;
        size_t remaining = text_size - offset;
        if (remaining > X86_MAX_INSTR_LEN) remaining = X86_MAX_INSTR_LEN;

        int consumed = x86_decode(text_host + offset, remaining,
                                   text_addr + offset, &instr);
        if (consumed <= 0) {
            printf("  0x%llx: <decode error> byte=0x%02x\n",
                   (unsigned long long)(text_addr + offset),
                   text_host[offset]);
            offset++;
            continue;
        }

        /* Print address */
        printf("  0x%llx: ", (unsigned long long)(text_addr + offset));

        /* Print hex bytes */
        for (int i = 0; i < consumed; i++) {
            printf("%02x ", text_host[offset + i]);
        }
        /* Pad to align mnemonics */
        for (int i = consumed; i < 10; i++) {
            printf("   ");
        }

        /* Print mnemonic */
        printf("  %s\n", x86_format_instr(&instr));

        offset += consumed;
    }

    macho_free(&binary);
    return 0;
}
