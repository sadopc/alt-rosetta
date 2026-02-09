/*
 * test_memory.c - Test load/store patterns
 *
 * Tests: MOV to/from memory, array indexing, struct-like access
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

    /* Test 1: Array write and read */
    test = 1;
    volatile int arr[10];
    for (int i = 0; i < 10; i++) {
        arr[i] = i * i;
    }
    if (arr[5] != 25) sys_exit(test);
    if (arr[9] != 81) sys_exit(test);

    /* Test 2: Byte access */
    test = 2;
    volatile char buf[4] = {'A', 'B', 'C', 'D'};
    if (buf[0] != 'A') sys_exit(test);
    if (buf[3] != 'D') sys_exit(test);

    /* Test 3: Pointer dereferencing */
    test = 3;
    volatile long val = 0xDEADBEEF;
    volatile long *ptr = &val;
    if (*ptr != 0xDEADBEEF) sys_exit(test);

    /* Test 4: Stack-allocated struct-like access */
    test = 4;
    volatile long fields[3];
    fields[0] = 100;
    fields[1] = 200;
    fields[2] = fields[0] + fields[1];
    if (fields[2] != 300) sys_exit(test);

    const char msg[] = "PASS\n";
    sys_write(1, msg, 5);
    sys_exit(0);
}
