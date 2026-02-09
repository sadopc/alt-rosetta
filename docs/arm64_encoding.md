# ARM64 (AArch64) Instruction Encoding

## Overview

ARM64 uses **fixed-width 32-bit** instruction encoding. Every instruction is exactly 4 bytes, aligned on a 4-byte boundary. This makes decoding much simpler than x86_64.

## Register File

- **X0-X30**: 64-bit general-purpose registers
- **W0-W30**: Lower 32 bits of X0-X30 (writing W clears upper 32 bits)
- **XZR/WZR**: Zero register (reads as 0, writes discarded) - encoded as register 31
- **SP**: Stack pointer (also encoded as 31, disambiguated by context)
- **PC**: Program counter (not directly accessible as a GPR)
- **V0-V31**: 128-bit NEON/FP registers (also accessible as B/H/S/D/Q)

## Encoding Classes

### Data Processing (Immediate)
```
sf | opc | 100xx | ... | Rd
```
ADD, SUB, AND, ORR, MOV (various), etc. with 12-bit or 16-bit immediates.

### Data Processing (Register)
```
sf | opc | xxxxx | shift | 0 | Rm | imm6 | Rn | Rd
```
ADD, SUB, AND, ORR, EOR with optional shifted register operand.

### Loads and Stores
```
size | 111 | V | opc | ... | Rn | Rt
```
- Unsigned offset: scaled by access size
- Pre/post-index: 9-bit signed offset
- Register offset: Rm with optional extend/shift

### Branches
```
opcode | imm26 (or imm19, imm14)
```
- B: 26-bit offset (±128 MB)
- B.cond: 19-bit offset (±1 MB)
- CBZ/CBNZ: 19-bit offset
- TBZ/TBNZ: 14-bit offset

## Condition Codes (NZCV)

| Code | Meaning | Flags |
|------|---------|-------|
| EQ | Equal | Z=1 |
| NE | Not equal | Z=0 |
| CS/HS | Carry set / unsigned >= | C=1 |
| CC/LO | Carry clear / unsigned < | C=0 |
| MI | Minus / negative | N=1 |
| PL | Plus / positive or zero | N=0 |
| VS | Overflow | V=1 |
| VC | No overflow | V=0 |
| HI | Unsigned > | C=1 and Z=0 |
| LS | Unsigned <= | C=0 or Z=1 |
| GE | Signed >= | N=V |
| LT | Signed < | N≠V |
| GT | Signed > | Z=0 and N=V |
| LE | Signed <= | Z=1 or N≠V |

## Important ARM64 ↔ x86 Flag Differences

The carry flag (C) has **opposite semantics for subtraction**:
- x86: CF=1 means borrow occurred (a < b in `SUB a, b`)
- ARM64: C=1 means NO borrow (a >= b in `SUBS`)

This means x86 JB (jump if CF=1) maps to ARM64 B.CC (branch if C=0).
