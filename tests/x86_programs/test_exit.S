/*
 * test_exit.S - Minimal x86_64 test: exit(42)
 *
 * Tests: MOV reg,imm + SYSCALL
 * Expected: exit code 42
 *
 * macOS x86_64 syscall convention:
 *   RAX = syscall number (with 0x2000000 class prefix)
 *   RDI = arg1
 *   SYSCALL instruction
 */

    .text
    .globl _start
    .p2align 4

_start:
    /* exit(42) */
    movq    $0x2000001, %rax    /* SYS_exit = 1, class UNIX = 0x2000000 */
    movq    $42, %rdi           /* exit code = 42 */
    syscall                     /* invoke kernel */

    /* Should never reach here */
    hlt
