# x86_64 Instruction Encoding

## Overview

x86_64 uses **variable-length** instruction encoding, where instructions can be anywhere from 1 to 15 bytes long. This makes decoding complex compared to fixed-width ISAs like ARM64.

## Instruction Format

```
[Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
```

Each component is optional depending on the instruction.

## Prefixes (0-4 bytes)

Legacy prefixes can appear in any order before the opcode:
- **66h**: Operand size override (switches 32-bit default to 16-bit)
- **67h**: Address size override
- **F0h**: LOCK (for atomic operations)
- **F2h**: REPNE/REPNZ (also used as SSE prefix)
- **F3h**: REP/REPE/REPZ (also used as SSE prefix)
- **26/2E/36/3E/64/65h**: Segment overrides (ES/CS/SS/DS/FS/GS)

## REX Prefix (0-1 byte, range 40h-4Fh)

In 64-bit mode, the REX prefix extends register addressing:
```
0100 W R X B
      |  | | |
      |  | | +-- Extends ModR/M rm or SIB base (B)
      |  | +---- Extends SIB index (X)
      |  +------ Extends ModR/M reg (R)
      +--------- 64-bit operand size (W)
```

## Opcode (1-3 bytes)

- **1-byte**: Most common instructions (e.g., 89h = MOV r/m, r)
- **2-byte**: 0Fh escape + second byte (e.g., 0F 84h = JE rel32)
- **3-byte**: 0F 38h or 0F 3Ah + third byte (SSE4, etc.)

## ModR/M byte

```
  7 6   5 4 3   2 1 0
[ mod ] [ reg ] [ rm ]
```

- **mod**: Addressing mode (00=no disp, 01=disp8, 10=disp32, 11=register)
- **reg**: Register operand or opcode extension (/digit)
- **rm**: Register/memory operand

When mod=00 and rm=101b: **RIP-relative addressing** (64-bit mode special case)

## SIB byte (when ModR/M rm=100b and mod≠11)

```
  7 6    5 4 3    2 1 0
[scale] [index] [ base ]
```

Effective address: `[base + index * (1 << scale) + displacement]`

## Key Differences from ARM64

| Feature | x86_64 | ARM64 |
|---------|--------|-------|
| Instruction size | 1-15 bytes | Fixed 4 bytes |
| Register count | 16 GPRs | 31 GPRs |
| Flags | Modified by most ALU ops | Only modified by explicit S-suffix |
| Memory operands | Can be in most instructions | Only in load/store |
| Immediates | Variable size, in instruction | Limited to specific ranges |
