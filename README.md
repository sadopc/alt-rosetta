# alt-rosetta

An educational x86_64 to ARM64 dynamic binary translator for macOS Apple Silicon, inspired by Apple's Rosetta 2.

Written in ~8,000 lines of C17 with zero external dependencies (only pthreads). Translates x86_64 Mach-O binaries to ARM64 at runtime via JIT compilation.

## How it works

```
x86_64 Mach-O binary
        |
   Mach-O Loader         Parse headers, map segments into memory
        |
   x86_64 Decoder         Decode variable-length instructions (prefixes, REX, ModR/M, SIB)
        |
  Pattern Translator      Match x86 instructions to ARM64 equivalents
        |
   ARM64 Emitter          Encode ARM64 instructions into machine code
        |
  Translation Cache       Cache translated blocks (FNV-1a hash table)
        |
   JIT Execution          Execute via MAP_JIT memory with W^X toggling
        |
      (loop)              Update RIP, translate next block
```

The translator works one **basic block** at a time. Each block is a sequence of x86 instructions ending at a branch, call, return, or syscall. Translated blocks are cached so they're only translated once.

### Key design decisions

**Lazy flags** - x86 sets EFLAGS on nearly every ALU instruction, but most are never read. Instead of computing all 6 flags after every instruction, we store the operation type and operands in dedicated ARM64 registers (X19, X25-X28) and only reconstruct flags when a conditional instruction (Jcc, SETcc, CMOVcc) actually needs them.

**Register mapping** - x86's 16 GPRs are mapped to ARM64 X0-X15. The remaining ARM64 registers serve as scratch space (X16-X17), lazy flags storage (X19, X25-X28), emulated RIP (X20), and translator context (X21-X24). X18 is never touched (reserved by macOS).

**Address translation** - Guest x86 code uses virtual addresses that don't correspond to host memory. Three resolution paths handle this: Mach-O segment mapping for code/data, JIT region mapping, and direct passthrough for stack addresses (which are host pointers from mmap).

## Building

Requires macOS on Apple Silicon and Xcode command-line tools.

```bash
make              # Build the translator
make sign         # Code-sign for MAP_JIT (required before running)
make tests        # Cross-compile x86_64 test binaries
make run-tests    # Build + sign + compile tests + run all tests
```

Other targets: `make debug` (ASan), `make release` (O2), `make tools` (Mach-O dumper + x86 disassembler), `make clean`.

## Usage

```bash
./build/alt-rosetta <x86_64-binary>

# With tracing
./build/alt-rosetta --trace-decode build/tests/test_flags    # Show decoded x86 instructions
./build/alt-rosetta --trace-emit build/tests/test_flags      # Show emitted ARM64 instructions
./build/alt-rosetta --trace-exec build/tests/test_flags      # Show register state at each block
./build/alt-rosetta --trace-all build/tests/test_flags       # All of the above
```

## Tests

Eight test programs cover the implemented instruction set. Each is a static x86_64 binary with no libc (raw syscalls only):

| Test | What it tests | Expected |
|------|---------------|----------|
| `test_exit` | Basic syscall | exit code 42 |
| `test_hello` | `write()` syscall | prints "Hello" |
| `test_arithmetic` | ADD, SUB, MUL, AND, OR, XOR, SHL, SHR, INC, DEC, NEG | prints "PASS" |
| `test_control_flow` | if/else, loops, function calls, recursion | prints "PASS" |
| `test_flags` | ZF, SF, CF, OF, signed/unsigned comparisons (JL, JGE, JLE, JG) | prints "PASS" |
| `test_fibonacci` | Recursive `fib(10)` via CALL/RET + stack frames | exit code 55 |
| `test_memory` | Stack loads/stores, pointer arithmetic | prints "PASS" |
| `test_syscall` | `write()` to stdout and stderr | prints "syscall test\nstderr ok" |

Run a single test:
```bash
./build/alt-rosetta build/tests/test_arithmetic
# or through the test harness:
bash tests/run_tests.sh test_arithmetic
```

## Project structure

```
src/
  main.c              Entry point, CLI argument parsing
  macho_loader.c      Mach-O parser and segment mapper
  x86_decode.c        x86_64 instruction decoder
  x86_tables.c        Opcode lookup tables (1-byte, 2-byte, groups)
  arm64_patterns.c    x86 → ARM64 translation patterns (~40 pattern functions)
  arm64_emit.c        ARM64 instruction encoder (60+ emit functions)
  translate.c         Main translation loop, execution trampoline (inline asm)
  cache.c             Translation cache (hash table with linear probing)
  memory.c            JIT memory manager (MAP_JIT, W^X, guest stack)
  flags.c             Lazy flags engine (set, compute, fused CMP+Jcc)
  syscall.c           x86_64 → ARM64 syscall remapping
  cpu_state.c         Guest CPU state management
  debug.c             Logging, tracing, disassembly output
  signal_handler.c    SIGSEGV/SIGBUS/SIGTRAP handlers for debugging
  ir.c, ir_opt.c      IR layer and optimizations (Phase 6+, scaffolding)
  simd.c              SSE → NEON stubs (Phase 9+)
include/              Headers for each module
tests/
  x86_programs/       x86_64 test sources (.S assembly, .c with inline asm)
  expected/           Expected output files (key=value: exit_code, stdout)
  run_tests.sh        Test runner script
docs/                 Architecture notes (x86/ARM64 encoding, macOS internals)
tools/                dump_macho and disasm_x86 utilities
```

## What's implemented (Phase 0-5)

- **Mach-O loading**: Parse x86_64 executables, map segments, resolve symbols
- **x86 decoding**: Variable-length instruction decoding with REX, ModR/M, SIB, prefixes
- **Instruction translation**: MOV, ADD, SUB, MUL, IMUL, DIV, AND, OR, XOR, NOT, NEG, SHL, SHR, SAR, CMP, TEST, LEA, INC, DEC, PUSH, POP, CALL, RET, JMP, Jcc, SETcc, CMOVcc, MOVZX, MOVSX, MOVSXD, CDQE, CDQ, CQO, XCHG, NOP, SYSCALL
- **Lazy flags**: Full EFLAGS reconstruction with correct operand-width handling
- **Translation cache**: FNV-1a hash table, avoids re-translating known blocks
- **Syscall handling**: exit, read, write (with guest → host pointer resolution)
- **JIT execution**: MAP_JIT with W^X toggle, inline-asm trampoline for state swap

## What's not implemented yet (Phase 6+)

- IR-based optimization (dead flag elimination, constant folding)
- Memory ordering (TSO enforcement via FEAT_TSO or barriers)
- Signal forwarding to guest handlers
- SSE/AVX → NEON translation
- Dynamic linking (dyld, shared libraries)
- Self-modifying code detection
- Multithreading

## License

Educational project. Use as you wish.
