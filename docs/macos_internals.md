# macOS Internals for Binary Translation

## Mach-O Binary Format

macOS executables use the Mach-O format (Mach Object). Key structures:

### Header (mach_header_64)
- `magic`: 0xFEEDFACF (64-bit)
- `cputype`: CPU_TYPE_X86_64 (0x01000007) for Intel binaries
- `filetype`: MH_EXECUTE (2) for executables
- `ncmds`: Number of load commands following the header

### Load Commands
- **LC_SEGMENT_64**: Defines a memory segment (address, size, file offset, protections)
- **LC_MAIN**: Specifies the entry point offset
- **LC_LOAD_DYLIB**: Names a dynamic library dependency
- **LC_SYMTAB**: Symbol table location

### Segments
- **__TEXT**: Read-only code and constants
- **__DATA**: Read-write global variables
- **__LINKEDIT**: Metadata for the dynamic linker
- **__PAGEZERO**: Unmapped region at address 0 (catches null pointer dereferences)

## macOS Syscall Convention

### x86_64
```
RAX = syscall number (OR'd with 0x2000000 for UNIX class)
RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4, R8 = arg5, R9 = arg6
SYSCALL instruction
Result in RAX, CF=1 on error
```

### ARM64
```
X16 = syscall number (no class prefix)
X0 = arg1, X1 = arg2, X2 = arg3, X3 = arg4, X4 = arg5, X5 = arg6
SVC #0x80
Result in X0, carry flag on error
```

Both architectures use the **same syscall numbers** on macOS.

## JIT Code Generation on macOS

### MAP_JIT
macOS requires the `MAP_JIT` flag for writable+executable memory:
```c
void *code = mmap(NULL, size,
    PROT_READ | PROT_WRITE | PROT_EXEC,
    MAP_PRIVATE | MAP_ANON | MAP_JIT, -1, 0);
```

### Write ↔ Execute Toggle (W^X)
MAP_JIT memory can be either writable OR executable, never both simultaneously:
```c
// Switch to writable mode
pthread_jit_write_protect_np(0);
// ... write ARM64 instructions ...

// Switch back to executable mode
pthread_jit_write_protect_np(1);
// Flush instruction cache
sys_icache_invalidate(code_ptr, code_size);
```

### Code Signing
JIT code requires the entitlement:
```xml
<key>com.apple.security.cs.allow-jit</key>
<true/>
```

Apply with: `codesign -s - --entitlements entitlements.plist --force binary`

## Memory Ordering: FEAT_TSO

Apple Silicon supports hardware TSO (Total Store Ordering) mode via the FEAT_TSO extension. When enabled, the CPU enforces x86-style memory ordering without explicit barrier instructions. This eliminates the need for DMB/LDAR/STLR around most memory accesses.

Check availability: `sysctl hw.optional.arm.FEAT_TSO`

## Page Size Differences

- x86_64 macOS: 4 KB pages (0x1000)
- ARM64 macOS: 16 KB pages (0x4000)

When loading x86_64 binaries, segments may be aligned to 4 KB boundaries. The translator must handle this by potentially over-allocating to meet 16 KB host page alignment.
