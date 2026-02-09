/*
 * test_flags.c - Test CMP + conditional branch combinations
 *
 * Tests various x86 condition codes through CMP + Jcc patterns.
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

    /* Test 1: ZF - zero flag (JE/JNE) */
    test = 1;
    volatile int a = 0;
    if (a != 0) sys_exit(test);

    /* Test 2: SF - sign flag (JS/JNS via < 0) */
    test = 2;
    volatile int neg = -5;
    if (neg >= 0) sys_exit(test);
    volatile int pos = 5;
    if (pos < 0) sys_exit(test);

    /* Test 3: CF - carry flag (JB/JAE via unsigned comparison) */
    test = 3;
    volatile unsigned int x = 1, y = 2;
    if (!(x < y)) sys_exit(test);

    /* Test 4: OF - overflow detection (signed overflow) */
    test = 4;
    volatile int big = 2000000000;
    volatile int also_big = 2000000000;
    volatile long long result = (long long)big + (long long)also_big;
    if (result != 4000000000LL) sys_exit(test);

    /* Test 5: Combined conditions - JLE (ZF=1 or SF!=OF) */
    test = 5;
    volatile int c = 10, d = 10;
    if (!(c <= d)) sys_exit(test);
    volatile int e = 5;
    if (!(e <= d)) sys_exit(test);

    /* Test 6: JG (ZF=0 and SF=OF) */
    test = 6;
    if (!(d > e)) sys_exit(test);
    if (e > d) sys_exit(test);

    /* All tests passed */
    const char msg[] = "PASS\n";
    sys_write(1, msg, 5);
    sys_exit(0);
}
