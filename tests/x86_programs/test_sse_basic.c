/*
 * test_sse_basic.c - Test basic SSE scalar float operations
 *
 * Tests: ADDSS, SUBSS, MULSS, DIVSS (scalar single-precision)
 * Exit code: 0 = pass
 */

static void sys_exit(int code) {
    __asm__ volatile(
        "movq $0x2000001, %%rax\n"
        "syscall\n"
        : : "D" (code) : "rax", "rcx", "r11"
    );
    __builtin_unreachable();
}

void _start(void) {
    int test = 0;

    /* Test 1: float addition */
    test = 1;
    volatile float a = 1.5f, b = 2.5f;
    volatile float sum = a + b;
    if (sum < 3.9f || sum > 4.1f) sys_exit(test);

    /* Test 2: float subtraction */
    test = 2;
    volatile float diff = b - a;
    if (diff < 0.9f || diff > 1.1f) sys_exit(test);

    /* Test 3: float multiplication */
    test = 3;
    volatile float prod = a * b;
    if (prod < 3.6f || prod > 3.8f) sys_exit(test);

    /* Test 4: float division */
    test = 4;
    volatile float quot = b / a;
    /* 2.5 / 1.5 ≈ 1.6667 */
    if (quot < 1.6f || quot > 1.7f) sys_exit(test);

    /* All pass */
    sys_exit(0);
}
