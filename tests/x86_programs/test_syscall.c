/*
 * test_syscall.c - Test multiple syscalls
 *
 * Tests: write() and exit() syscalls
 * Expected output: "syscall test\n"
 * Expected exit code: 0
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
    /* Multiple write syscalls */
    const char msg1[] = "syscall ";
    const char msg2[] = "test\n";

    long ret1 = sys_write(1, msg1, 8);
    if (ret1 < 0) sys_exit(1);

    long ret2 = sys_write(1, msg2, 5);
    if (ret2 < 0) sys_exit(2);

    /* Write to stderr too */
    const char err_msg[] = "stderr ok\n";
    sys_write(2, err_msg, 10);

    sys_exit(0);
}
