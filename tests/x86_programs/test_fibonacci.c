/*
 * test_fibonacci.c - Recursive Fibonacci to test CALL/RET + stack
 *
 * Tests: PUSH, POP, CALL, RET, CMP, Jcc, ADD, SUB
 * Expected exit code: fib(10) = 55
 */

static void sys_exit(int code) {
    __asm__ volatile(
        "movq $0x2000001, %%rax\n"
        "syscall\n"
        : : "D" (code) : "rax", "rcx", "r11"
    );
    __builtin_unreachable();
}

static int fibonacci(int n) {
    if (n <= 0) return 0;
    if (n == 1) return 1;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

void _start(void) {
    int result = fibonacci(10);
    /* fib(10) = 55 */
    sys_exit(result);  /* Exit with 55 */
}
