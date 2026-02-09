/*
 * test_control_flow.c - Test control flow: if/else, loops, function calls
 *
 * Tests: CMP, Jcc, CALL, RET, JMP
 * Exit code: 0 = pass, non-zero = first failing test number
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

/* Simple function to test CALL/RET */
static int add_numbers(int a, int b) {
    return a + b;
}

static int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

void _start(void) {
    int test = 0;

    /* Test 1: if/else (CMP + JE/JNE) */
    test = 1;
    volatile int a = 42;
    if (a != 42) sys_exit(test);

    /* Test 2: less than / greater than */
    test = 2;
    volatile int b = 10, c = 20;
    if (!(b < c)) sys_exit(test);
    if (!(c > b)) sys_exit(test);

    /* Test 3: function call and return */
    test = 3;
    int sum = add_numbers(17, 25);
    if (sum != 42) sys_exit(test);

    /* Test 4: loop (for) */
    test = 4;
    volatile int total = 0;
    for (int i = 0; i < 10; i++) {
        total += i;
    }
    if (total != 45) sys_exit(test);  /* 0+1+2+...+9 = 45 */

    /* Test 5: while loop */
    test = 5;
    volatile int count = 0;
    volatile int x = 100;
    while (x > 0) {
        x -= 10;
        count++;
    }
    if (count != 10) sys_exit(test);

    /* Test 6: recursive function call */
    test = 6;
    int f = factorial(5);
    if (f != 120) sys_exit(test);

    /* All tests passed */
    const char msg[] = "PASS\n";
    sys_write(1, msg, 5);
    sys_exit(0);
}
