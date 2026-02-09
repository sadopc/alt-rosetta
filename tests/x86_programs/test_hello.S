/*
 * test_hello.S - x86_64 test: write "Hello\n" to stdout, then exit(0)
 *
 * Tests: MOV reg,imm + LEA (RIP-relative) + SYSCALL (write + exit)
 * Expected output: "Hello\n"
 * Expected exit code: 0
 */

    .text
    .globl _start
    .p2align 4

_start:
    /* write(1, msg, 6) */
    movq    $0x2000004, %rax    /* SYS_write = 4 */
    movq    $1, %rdi            /* fd = stdout */
    leaq    msg(%rip), %rsi     /* buf = &msg (RIP-relative) */
    movq    $6, %rdx            /* count = 6 */
    syscall

    /* exit(0) */
    movq    $0x2000001, %rax    /* SYS_exit = 1 */
    xorq    %rdi, %rdi          /* exit code = 0 */
    syscall

    hlt

    .data
msg:
    .ascii "Hello\n"
