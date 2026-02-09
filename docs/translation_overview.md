# Binary Translation Overview

## What is Binary Translation?

Binary translation converts machine code from one CPU architecture to another, enabling programs compiled for one processor to run on a different one. Apple's Rosetta 2 translates x86_64 code to ARM64 on Apple Silicon Macs.

## Translation Approaches

### Static Binary Translation (SBT)
Translates the entire binary ahead of time, producing a native executable. Difficult because it's hard to distinguish code from data and handle indirect branches.

### Dynamic Binary Translation (DBT) - Our Approach
Translates code at runtime, one basic block at a time:

1. **Fetch**: Read x86_64 instructions from the guest binary
2. **Decode**: Parse variable-length x86 instructions into structured form
3. **Translate**: Convert to ARM64 instructions (directly or via IR)
4. **Cache**: Store translations for reuse
5. **Execute**: Jump to translated ARM64 code

This handles indirect branches naturally since we translate as we go.

## Basic Blocks

A **basic block** is a sequence of instructions with:
- One entry point (the first instruction)
- One exit point (the last instruction)
- No branches in the middle

Block terminators: JMP, Jcc, CALL, RET, SYSCALL

## Key Challenges

### Register Mapping
x86_64 has 16 GPRs, ARM64 has 31. We dedicate ARM64 registers to hold x86 state:
- X0-X15: Guest x86 GPRs
- X16-X17: Scratch registers
- X19-X28: Translator metadata (flags, RIP, context)

### Flag Computation
x86 modifies flags (CF, ZF, SF, OF, PF, AF) on nearly every ALU instruction.
ARM64 only modifies NZCV with explicit S-suffix instructions.

**Lazy flags**: Instead of computing all flags after every instruction, we store the operation and operands. When a conditional instruction actually reads flags, we compute only what's needed.

### Memory Ordering
x86 has Total Store Order (TSO) - stores are seen in program order.
ARM64 is weakly ordered by default. Apple Silicon has FEAT_TSO hardware mode to match x86 ordering without barriers.

### W^X (Write XOR Execute)
macOS enforces that memory cannot be both writable and executable simultaneously.
We use MAP_JIT memory and toggle between write/execute modes.

## Translation Pipeline

```
x86 binary → Mach-O Loader → x86 Decoder → [IR Builder → IR Optimizer] → ARM64 Emitter → JIT Cache → Execute
```

The IR layer is optional. Direct translation (x86 → ARM64 patterns) is simpler and sufficient for many instructions. The IR enables optimizations like dead flag elimination.
