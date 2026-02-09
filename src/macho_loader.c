/*
 * macho_loader.c - Mach-O binary parser for x86_64 executables
 *
 * Parses Mach-O headers, load commands, and maps segments into host memory
 * for the binary translator to operate on.
 */

#include "macho_loader.h"
#include "memory.h"
#include "debug.h"
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <mach-o/loader.h>

/* Convert Mach-O VM protection flags to mmap PROT flags */
static int vmprot_to_prot(uint32_t vmprot)
{
    int prot = 0;
    if (vmprot & VM_PROT_READ)
        prot |= PROT_READ;
    if (vmprot & VM_PROT_WRITE)
        prot |= PROT_WRITE;
    if (vmprot & VM_PROT_EXECUTE)
        prot |= PROT_EXEC;
    return prot;
}

/* Round up to the host page size (16KB on Apple Silicon) */
static size_t page_align(size_t size)
{
    size_t page = (size_t)getpagesize();
    return (size + page - 1) & ~(page - 1);
}

int macho_load(const char *path, macho_binary_t *binary)
{
    int fd = -1;
    struct stat st;

    if (!path || !binary) {
        LOG_ERR("macho_load: NULL argument");
        return -1;
    }

    memset(binary, 0, sizeof(*binary));

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        LOG_ERR("macho_load: failed to open '%s'", path);
        return -1;
    }

    if (fstat(fd, &st) < 0) {
        LOG_ERR("macho_load: fstat failed for '%s'", path);
        close(fd);
        return -1;
    }

    binary->file_size = (size_t)st.st_size;
    if (binary->file_size < sizeof(struct mach_header_64)) {
        LOG_ERR("macho_load: file too small (%zu bytes)", binary->file_size);
        close(fd);
        return -1;
    }

    binary->file_data = mmap(NULL, binary->file_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);

    if (binary->file_data == MAP_FAILED) {
        LOG_ERR("macho_load: mmap failed for '%s'", path);
        binary->file_data = NULL;
        return -1;
    }

    /* Parse the Mach-O 64-bit header */
    const struct mach_header_64 *hdr = (const struct mach_header_64 *)binary->file_data;

    if (hdr->magic != MH_MAGIC_64) {
        LOG_ERR("macho_load: bad magic 0x%08x (expected 0x%08x)", hdr->magic, MH_MAGIC_64);
        macho_free(binary);
        return -1;
    }

    if (hdr->cputype != CPU_TYPE_X86_64) {
        LOG_ERR("macho_load: not x86_64 (cputype=0x%08x)", hdr->cputype);
        macho_free(binary);
        return -1;
    }

    if (hdr->filetype != MH_EXECUTE) {
        LOG_ERR("macho_load: not an executable (filetype=%u)", hdr->filetype);
        macho_free(binary);
        return -1;
    }

    binary->magic      = hdr->magic;
    binary->cputype    = hdr->cputype;
    binary->cpusubtype = hdr->cpusubtype;
    binary->filetype   = hdr->filetype;
    binary->ncmds      = hdr->ncmds;
    binary->sizeofcmds = hdr->sizeofcmds;
    binary->flags      = hdr->flags;

    LOG_INFO("macho_load: parsing %u load commands", hdr->ncmds);

    /* Walk load commands */
    const uint8_t *cmd_ptr = binary->file_data + sizeof(struct mach_header_64);
    const uint8_t *cmd_end = cmd_ptr + hdr->sizeofcmds;
    bool found_entry = false;

    for (uint32_t i = 0; i < hdr->ncmds; i++) {
        if (cmd_ptr + sizeof(struct load_command) > cmd_end) {
            LOG_ERR("macho_load: load command %u overflows", i);
            macho_free(binary);
            return -1;
        }

        const struct load_command *lc = (const struct load_command *)cmd_ptr;

        if (lc->cmdsize < sizeof(struct load_command) || cmd_ptr + lc->cmdsize > cmd_end) {
            LOG_ERR("macho_load: load command %u has invalid size %u", i, lc->cmdsize);
            macho_free(binary);
            return -1;
        }

        switch (lc->cmd) {
        case LC_SEGMENT_64: {
            if (lc->cmdsize < sizeof(struct segment_command_64)) {
                LOG_ERR("macho_load: LC_SEGMENT_64 too small");
                macho_free(binary);
                return -1;
            }
            const struct segment_command_64 *seg = (const struct segment_command_64 *)cmd_ptr;

            if (binary->num_segments >= MAX_SEGMENTS) {
                LOG_WARN("macho_load: too many segments, skipping '%s'", seg->segname);
                break;
            }

            mapped_segment_t *ms = &binary->segments[binary->num_segments];
            memcpy(ms->segname, seg->segname, 16);
            ms->vmaddr   = seg->vmaddr;
            ms->vmsize   = seg->vmsize;
            ms->fileoff  = seg->fileoff;
            ms->filesize = seg->filesize;
            ms->maxprot  = seg->maxprot;
            ms->initprot = seg->initprot;
            ms->host_addr = NULL;

            /* Track __TEXT base address for entry point calculation */
            if (strncmp(seg->segname, "__TEXT", 6) == 0) {
                binary->text_vmaddr = seg->vmaddr;
            }

            LOG_DBG("  segment %-16s vmaddr=0x%llx vmsize=0x%llx fileoff=0x%llx filesize=0x%llx",
                     seg->segname, seg->vmaddr, seg->vmsize, seg->fileoff, seg->filesize);

            binary->num_segments++;
            break;
        }

        case LC_MAIN: {
            if (lc->cmdsize < sizeof(struct entry_point_command)) {
                LOG_ERR("macho_load: LC_MAIN too small");
                macho_free(binary);
                return -1;
            }
            const struct entry_point_command *ep = (const struct entry_point_command *)cmd_ptr;
            binary->entry_point = binary->text_vmaddr + ep->entryoff;
            found_entry = true;
            LOG_DBG("  LC_MAIN: entryoff=0x%llx -> entry_point=0x%llx",
                     ep->entryoff, binary->entry_point);
            break;
        }

        case LC_SYMTAB: {
            if (lc->cmdsize < sizeof(struct symtab_command)) {
                LOG_ERR("macho_load: LC_SYMTAB too small");
                macho_free(binary);
                return -1;
            }
            const struct symtab_command *sym = (const struct symtab_command *)cmd_ptr;

            if (sym->symoff + sym->nsyms * sizeof(struct nlist_64) > binary->file_size) {
                LOG_WARN("macho_load: symbol table extends beyond file");
                break;
            }
            if (sym->stroff + sym->strsize > binary->file_size) {
                LOG_WARN("macho_load: string table extends beyond file");
                break;
            }

            binary->symtab  = (struct nlist_64 *)(binary->file_data + sym->symoff);
            binary->nsyms   = sym->nsyms;
            binary->strtab  = (char *)(binary->file_data + sym->stroff);
            binary->strsize = sym->strsize;

            LOG_DBG("  LC_SYMTAB: %u symbols, strsize=%u", sym->nsyms, sym->strsize);
            break;
        }

        case LC_LOAD_DYLIB:
        case LC_LOAD_WEAK_DYLIB:
        case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB: {
            if (lc->cmdsize < sizeof(struct dylib_command)) {
                LOG_WARN("macho_load: dylib command too small");
                break;
            }
            const struct dylib_command *dc = (const struct dylib_command *)cmd_ptr;
            uint32_t name_off = dc->dylib.name.offset;

            if (name_off >= lc->cmdsize) {
                LOG_WARN("macho_load: dylib name offset out of range");
                break;
            }

            const char *dylib_name = (const char *)cmd_ptr + name_off;
            /* Ensure the name is within the command bounds */
            size_t max_len = lc->cmdsize - name_off;

            if (binary->num_dylibs >= MAX_DYLIBS) {
                LOG_WARN("macho_load: too many dylibs, skipping '%s'", dylib_name);
                break;
            }

            binary->dylibs[binary->num_dylibs] = strndup(dylib_name, max_len);
            if (!binary->dylibs[binary->num_dylibs]) {
                LOG_ERR("macho_load: strndup failed for dylib name");
                macho_free(binary);
                return -1;
            }

            LOG_DBG("  dylib: %s", binary->dylibs[binary->num_dylibs]);
            binary->num_dylibs++;
            break;
        }

        case LC_UNIXTHREAD: {
            /* Fallback for older binaries that lack LC_MAIN.
             * The thread state contains the initial RIP in the x86_thread_state64. */
            if (!found_entry && lc->cmdsize >= 184) {
                /* x86_64 thread state layout in LC_UNIXTHREAD:
                 *   +0  cmd, cmdsize
                 *   +8  flavor (4 bytes, should be x86_THREAD_STATE64 = 4)
                 *   +12 count  (4 bytes)
                 *   +16 state  (x86_thread_state64: rax at +0, rip at +128)
                 * rip offset from cmd_ptr = 16 + 128 = 144 */
                const uint64_t *rip_ptr = (const uint64_t *)(cmd_ptr + 16 + 128);
                binary->entry_point = *rip_ptr;
                found_entry = true;
                LOG_DBG("  LC_UNIXTHREAD: rip=0x%llx", binary->entry_point);
            }
            break;
        }

        default:
            LOG_DBG("  load command 0x%x (size %u) - skipped", lc->cmd, lc->cmdsize);
            break;
        }

        cmd_ptr += lc->cmdsize;
    }

    if (!found_entry) {
        LOG_ERR("macho_load: no entry point found (no LC_MAIN or LC_UNIXTHREAD)");
        macho_free(binary);
        return -1;
    }

    LOG_INFO("macho_load: loaded '%s' - %d segments, %d dylibs, entry=0x%llx",
             path, binary->num_segments, binary->num_dylibs, binary->entry_point);

    return 0;
}

int macho_map_segments(macho_binary_t *binary)
{
    if (!binary || !binary->file_data) {
        LOG_ERR("macho_map_segments: invalid binary");
        return -1;
    }

    for (int i = 0; i < binary->num_segments; i++) {
        mapped_segment_t *seg = &binary->segments[i];

        if (seg->vmsize == 0) {
            LOG_DBG("  segment '%s' has vmsize=0, skipping map", seg->segname);
            continue;
        }

        /* Skip __PAGEZERO - it's a guard region, not real memory */
        if (strcmp(seg->segname, "__PAGEZERO") == 0) {
            LOG_DBG("  segment '__PAGEZERO' is guard region, skipping map");
            continue;
        }

        /* Ensure allocation is aligned to host page size (16KB on Apple Silicon).
         * x86_64 binaries may use 4KB alignment, but our host requires 16KB. */
        size_t alloc_size = page_align(seg->vmsize);

        /* Allocate anonymous memory, initially writable so we can copy data in */
        uint8_t *host_addr = mmap(NULL, alloc_size,
                                  PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANON, -1, 0);
        if (host_addr == MAP_FAILED) {
            LOG_ERR("macho_map_segments: mmap failed for segment '%s' (size 0x%llx)",
                    seg->segname, (unsigned long long)alloc_size);
            return -1;
        }

        /* Copy file data into the segment. MAP_ANON guarantees the rest is zeroed. */
        if (seg->filesize > 0) {
            if (seg->fileoff + seg->filesize > binary->file_size) {
                LOG_ERR("macho_map_segments: segment '%s' filedata extends beyond file", seg->segname);
                munmap(host_addr, alloc_size);
                return -1;
            }
            memcpy(host_addr, binary->file_data + seg->fileoff, seg->filesize);
        }

        /* Set final protection based on initprot.
         * Skip mprotect if the segment is already RW (common for __DATA). */
        int final_prot = vmprot_to_prot(seg->initprot);
        if (final_prot != (PROT_READ | PROT_WRITE)) {
            /* On Apple Silicon we cannot have PROT_EXEC on non-MAP_JIT memory
             * for data we wrote. For translated code, we won't execute x86 code
             * directly, so map it read-only or read-write as appropriate.
             * Keep PROT_EXEC in the protection but note the host kernel may
             * enforce W^X. For our purposes the translator reads from these
             * segments, it doesn't execute them directly. */
            if (mprotect(host_addr, alloc_size, final_prot) < 0) {
                /* If PROT_EXEC fails (W^X), retry without it - we only need to read */
                int fallback = final_prot & ~PROT_EXEC;
                if (fallback == 0)
                    fallback = PROT_READ;
                if (mprotect(host_addr, alloc_size, fallback) < 0) {
                    LOG_ERR("macho_map_segments: mprotect failed for '%s'", seg->segname);
                    munmap(host_addr, alloc_size);
                    return -1;
                }
                LOG_DBG("  segment '%s' mapped without PROT_EXEC (W^X fallback)", seg->segname);
            }
        }

        seg->host_addr = host_addr;

        LOG_DBG("  mapped '%s': guest 0x%llx -> host %p (size 0x%llx, prot 0x%x)",
                seg->segname, seg->vmaddr, (void *)host_addr,
                (unsigned long long)alloc_size, seg->initprot);
    }

    LOG_INFO("macho_map_segments: mapped %d segments", binary->num_segments);
    return 0;
}

uint64_t macho_lookup_symbol(const macho_binary_t *binary, const char *name)
{
    if (!binary || !name || !binary->symtab || !binary->strtab)
        return 0;

    for (uint32_t i = 0; i < binary->nsyms; i++) {
        const struct nlist_64 *nl = &binary->symtab[i];
        uint32_t strx = nl->n_un.n_strx;

        if (strx >= binary->strsize)
            continue;

        const char *sym_name = binary->strtab + strx;

        /* Mach-O symbols have a leading underscore; match against both forms */
        if (strcmp(sym_name, name) == 0)
            return nl->n_value;

        /* If caller passed "main", also match "_main" */
        if (sym_name[0] == '_' && strcmp(sym_name + 1, name) == 0)
            return nl->n_value;
    }

    return 0;
}

uint8_t *macho_guest_to_host(const macho_binary_t *binary, uint64_t guest_addr)
{
    if (!binary)
        return NULL;

    for (int i = 0; i < binary->num_segments; i++) {
        const mapped_segment_t *seg = &binary->segments[i];
        if (seg->host_addr &&
            guest_addr >= seg->vmaddr &&
            guest_addr < seg->vmaddr + seg->vmsize) {
            return seg->host_addr + (guest_addr - seg->vmaddr);
        }
    }

    return NULL;
}

void macho_free(macho_binary_t *binary)
{
    if (!binary)
        return;

    /* Unmap file data */
    if (binary->file_data) {
        munmap(binary->file_data, binary->file_size);
    }

    /* Unmap segments */
    for (int i = 0; i < binary->num_segments; i++) {
        mapped_segment_t *seg = &binary->segments[i];
        if (seg->host_addr) {
            size_t alloc_size = page_align(seg->vmsize);
            munmap(seg->host_addr, alloc_size);
        }
    }

    /* Free dylib name strings */
    for (int i = 0; i < binary->num_dylibs; i++) {
        free(binary->dylibs[i]);
    }

    memset(binary, 0, sizeof(*binary));
}

void macho_dump(const macho_binary_t *binary)
{
    if (!binary) {
        printf("(null binary)\n");
        return;
    }

    printf("=== Mach-O Binary ===\n");
    printf("  magic:      0x%08x\n", binary->magic);
    printf("  cputype:    0x%08x\n", binary->cputype);
    printf("  cpusubtype: 0x%08x\n", binary->cpusubtype);
    printf("  filetype:   %u\n", binary->filetype);
    printf("  ncmds:      %u\n", binary->ncmds);
    printf("  flags:      0x%08x\n", binary->flags);
    printf("  entry:      0x%llx\n", binary->entry_point);
    printf("\n");

    printf("Segments (%d):\n", binary->num_segments);
    for (int i = 0; i < binary->num_segments; i++) {
        const mapped_segment_t *seg = &binary->segments[i];
        printf("  [%2d] %-16s vmaddr=0x%012llx vmsize=0x%08llx "
               "fileoff=0x%08llx filesize=0x%08llx "
               "maxprot=0x%x initprot=0x%x host=%p\n",
               i, seg->segname,
               seg->vmaddr, seg->vmsize,
               seg->fileoff, seg->filesize,
               seg->maxprot, seg->initprot,
               (void *)seg->host_addr);
    }
    printf("\n");

    if (binary->num_dylibs > 0) {
        printf("Dylibs (%d):\n", binary->num_dylibs);
        for (int i = 0; i < binary->num_dylibs; i++) {
            printf("  [%2d] %s\n", i, binary->dylibs[i]);
        }
        printf("\n");
    }

    if (binary->symtab) {
        printf("Symbol table: %u symbols, string table %u bytes\n",
               binary->nsyms, binary->strsize);
    } else {
        printf("No symbol table\n");
    }
}
