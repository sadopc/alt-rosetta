# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Alternative Rosetta — educational x86_64 → ARM64 dynamic binary translator for macOS Apple Silicon. Written in C17, no external dependencies beyond pthreads.

## Build & Test

```bash
make                  # Build (output: build/alt-rosetta)
make sign             # Code-sign for MAP_JIT (required before running)
make tests            # Cross-compile x86_64 test binaries
make run-tests        # Build + sign + compile tests + run all tests
make debug            # Build with -O0 -g -fsanitize=address
make release          # Build with -O2
make tools            # Build dump_macho and disasm_x86 utilities

# Run a single test
./build/alt-rosetta build/tests/test_arithmetic

# Run one test through the test harness
bash tests/run_tests.sh test_arithmetic

# Trace/debug flags
./build/alt-rosetta --trace-decode build/tests/test_flags
./build/alt-rosetta --trace-all build/tests/test_flags
```

Test binaries are x86_64 static executables with no libc. Assembly tests use `-Wl,-e,_start`, C tests use `-Wl,-e,__start` (macOS adds underscore prefix). C tests require `-fno-stack-protector`. Expected results are in `tests/expected/*.expected` (key=value: `exit_code`, `stdout`).

## Architecture

**Translation pipeline:** Mach-O loader → x86 decoder → pattern translator → ARM64 emitter → JIT execute

The main loop in `translate.c::translator_run` repeatedly: (1) looks up RIP in the translation cache, (2) if miss, decodes an x86 basic block until a terminator (JMP/Jcc/CALL/RET/SYSCALL), (3) translates each instruction via pattern functions in `arm64_patterns.c`, (4) caches the ARM64 code, (5) executes via inline-asm trampoline that swaps host/guest register state.

### Register mapping

x86 GPRs live in ARM64 X0-X15 at runtime. The mapping is **not identity** for RSP/RBP/RSI/RDI — use `x86_to_arm_reg()` from `alt_rosetta.h`:

| x86 | ARM64 | x86 | ARM64 |
|-----|-------|-----|-------|
| RAX | X0 | RSI | X4 |
| RCX | X1 | RDI | X5 |
| RDX | X2 | RSP | X6 |
| RBX | X3 | RBP | X7 |
| R8-R15 | X8-X15 | | |

Special registers: X16-X17 = scratch, X18 = **never touch** (macOS reserved), X19 = flags op type, X20 = emulated RIP, X21 = cpu_state pointer, X22-X24 = temporaries, X25-X28 = lazy flags state (op1, op2, result, size), X29-X30 = host FP/LR.

### Lazy flags

x86 sets EFLAGS on every ALU op but rarely reads them. Instead of computing flags eagerly, we store `{op_type, op1, op2, result, size}` in X19/X25-X28 and reconstruct NZCV on demand in `emit_compute_flags()` (flags.c) when a Jcc/SETcc/CMOVcc needs them. The reconstruction SUBS/ADDS **must match the original operand width** (sf=0 for 32-bit, sf=1 for 64-bit) — using 64-bit unconditionally gives wrong N/V flags for 32-bit ops.

### Address translation

Guest code uses x86 virtual addresses. Three resolution paths exist for converting guest → host addresses:
1. `macho_guest_to_host()` — Mach-O mapped segments (code, data)
2. `jit_guest_to_host()` — JIT guest regions
3. Stack addresses are already host pointers (mmap'd directly)

`emit_lea_to_scratch()` in `arm64_patterns.c` handles this: pass `ctx=NULL` for LEA (keeps guest address), pass `ctx` for actual memory loads/stores (resolves to host address). `resolve_guest_ptr()` in `syscall.c` tries all three paths for syscall buffer pointers.

### cpu_state struct offsets (used in inline asm)

`gpr[16]` at offset 0, `rip` at 128, `flags_op` at 136, `flags_op1` at 144, `flags_op2` at 152, `flags_res` at 160, `flags_size` at 168.

## Key patterns to follow

- Pattern functions in `arm64_patterns.c` return 0 on success, -1 on failure. Dispatch is in `translate_instr_direct()`.
- Emit functions take `jit_memory_t *jit` and append one 32-bit ARM64 instruction.
- When SUBS/ADDS result is used for lazy flags, the destination register **must not alias** an input register that `emit_set_lazy_flags` reads afterward. Use ARM_TMP0 (X22) for throw-away results like CMP/TEST.
- W^X: call `jit_begin_write()` before emitting, `jit_end_write()` after (toggles `pthread_jit_write_protect_np` + icache invalidate).
- The execution trampoline in `translate.c::execute_block` uses inline asm to load guest state from cpu_state into X0-X15/X19-X28, BLR to translated code, then store back. RIP is written to memory (`str x20, [x21, #128]`) not via an output operand.

## Status

Phase 0-5 complete, all 8 tests pass. Phase 6+ (IR optimization, memory model, signals, SSE→NEON, dynamic linking) is TODO.
