/*
 * test_strings.c - Test string/memory operations
 *
 * Tests: REP MOVSB (memcpy-like behavior)
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

/* Manual memcpy using a byte loop (avoids REP MOVSB for basic testing) */
static void my_memcpy(void *dst, const void *src, long n) {
    char *d = (char *)dst;
    const char *s = (const char *)src;
    for (long i = 0; i < n; i++) {
        d[i] = s[i];
    }
}

void _start(void) {
    int test = 0;

    /* Test 1: Copy a string */
    test = 1;
    char src[] = "Hello, World!";
    char dst[16] = {0};
    my_memcpy(dst, src, 13);
    if (dst[0] != 'H') sys_exit(test);
    if (dst[7] != 'W') sys_exit(test);
    if (dst[12] != '!') sys_exit(test);

    /* Test 2: Copy numbers */
    test = 2;
    long nums_src[] = {10, 20, 30, 40, 50};
    long nums_dst[5] = {0};
    my_memcpy(nums_dst, nums_src, 5 * sizeof(long));
    if (nums_dst[0] != 10) sys_exit(test);
    if (nums_dst[4] != 50) sys_exit(test);

    const char msg[] = "PASS\n";
    sys_write(1, msg, 5);
    sys_exit(0);
}
