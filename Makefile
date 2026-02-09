CC = clang
CFLAGS = -Wall -Wextra -Wpedantic -std=c17 -arch arm64 -Iinclude
LDFLAGS = -lpthread
SRCS = $(wildcard src/*.c)
OBJS = $(SRCS:src/%.c=build/%.o)
TARGET = build/alt-rosetta

.PHONY: all debug release sign tests clean tools

all: $(TARGET)

debug: CFLAGS += -O0 -g -DDEBUG -fsanitize=address
debug: LDFLAGS += -fsanitize=address
debug: $(TARGET)

release: CFLAGS += -O2 -g
release: $(TARGET)

$(TARGET): $(OBJS) | build
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build build/tests

sign: $(TARGET)
	codesign -s - --entitlements entitlements.plist --force $<

tools: build/dump_macho build/disasm_x86

build/dump_macho: tools/dump_macho.c | build
	$(CC) $(CFLAGS) -o $@ $<

build/disasm_x86: tools/disasm_x86.c | build
	$(CC) $(CFLAGS) -Iinclude src/x86_decode.c src/x86_tables.c src/debug.c -o $@ $<

# Cross-compile x86_64 test programs (static, no libc)
X86_ASM_TESTS = build/tests/test_exit build/tests/test_hello
X86_C_TESTS = build/tests/test_arithmetic build/tests/test_control_flow \
              build/tests/test_flags build/tests/test_fibonacci \
              build/tests/test_memory build/tests/test_syscall
tests: $(X86_ASM_TESTS) $(X86_C_TESTS)

build/tests/test_exit: tests/x86_programs/test_exit.S | build
	$(CC) -arch x86_64 -nostdlib -static -Wl,-e,_start -o $@ $<

build/tests/test_hello: tests/x86_programs/test_hello.S | build
	$(CC) -arch x86_64 -nostdlib -static -Wl,-e,_start -o $@ $<

build/tests/test_%: tests/x86_programs/test_%.c | build
	$(CC) -arch x86_64 -static -nostdlib -fno-stack-protector -Wl,-e,__start -o $@ $<

# Run all tests
run-tests: all sign tests
	@bash tests/run_tests.sh

clean:
	rm -rf build/
