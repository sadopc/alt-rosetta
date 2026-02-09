/*
 * test_arithmetic.c - Test basic arithmetic operations
 *
 * This is a C source that would be compiled with:
 *   clang -arch x86_64 -static -nostdlib -e _start -o test_arithmetic test_arithmetic.c
 *
 * Tests: ADD, SUB, MUL (IMUL), AND, OR, XOR, SHL, SHR, INC, DEC, NEG
 * Exit code encodes pass/fail: 0 = all pass, non-zero = first failing test number
 */

/* Raw syscall wrappers for x86_64 macOS */
static void sys_exit(int code) {
    __asm__ volatile(
        "movq $0x2000001, %%rax\n"
        "syscall\n"
        : : "D" (code) : "rax", "rcx", "r11"
    );
    __builtin_unreachable();
}

static long sys_write(int fd, const void *buf, long count) {
    long ret;
    __asm__ volatile(
        "movq $0x2000004, %%rax\n"
        "syscall\n"
        : "=a" (ret)
        : "D" (fd), "S" (buf), "d" (count)
        : "rcx", "r11", "memory"
    );
    return ret;
}

void _start(void) {
    int test = 0;

    /* Test 1: ADD */
    test = 1;
    volatile long a = 10, b = 20;
    if (a + b != 30) sys_exit(test);

    /* Test 2: SUB */
    test = 2;
    if (a - b != -10) sys_exit(test);

    /* Test 3: MUL */
    test = 3;
    if (a * b != 200) sys_exit(test);

    /* Test 4: AND */
    test = 4;
    volatile long x = 0xFF, y = 0x0F;
    if ((x & y) != 0x0F) sys_exit(test);

    /* Test 5: OR */
    test = 5;
    if ((x | y) != 0xFF) sys_exit(test);

    /* Test 6: XOR */
    test = 6;
    if ((x ^ y) != 0xF0) sys_exit(test);

    /* Test 7: SHL */
    test = 7;
    volatile long v = 1;
    if ((v << 4) != 16) sys_exit(test);

    /* Test 8: SHR */
    test = 8;
    volatile unsigned long u = 256;
    if ((u >> 4) != 16) sys_exit(test);

    /* Test 9: INC/DEC (via ++ and --) */
    test = 9;
    volatile long c = 41;
    c++;
    if (c != 42) sys_exit(test);
    c--;
    if (c != 41) sys_exit(test);

    /* Test 10: NEG */
    test = 10;
    volatile long n = 42;
    n = -n;
    if (n != -42) sys_exit(test);

    /* All tests passed */
    const char msg[] = "PASS\n";
    sys_write(1, msg, 5);
    sys_exit(0);
}
