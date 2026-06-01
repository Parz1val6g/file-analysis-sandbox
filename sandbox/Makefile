# Makefile — Sandbox File Analysis Engine (C Only)
#
# Targets:
#   make              Release build (-O3 -flto -march=native)
#   make debug        Debug build with ASAN + UBSAN
#   make test         Run unit tests
#   make chaos        Run chaos/stress test suite
#   make clean        Remove build artifacts

CC       ?= gcc
SRCDIR   = src
TESTDIR  = tests
TARGET   = sandbox_engine
TESTBIN  = test_runner
CHAOSBIN = chaos_runner
ifeq ($(OS),Windows_NT)
    TARGET   := $(TARGET).exe
    TESTBIN  := $(TESTBIN).exe
    CHAOSBIN := $(CHAOSBIN).exe
endif

# ── Flags ──────────────────────────────────────────────────────────────

# TCC has limited flag support — keep it simple
ifeq ($(CC),tcc)
    RELEASE_CFLAGS = -Wall
    DEBUG_CFLAGS   = -Wall -g
else
    RELEASE_CFLAGS = -Wall -Wextra -Werror \
                     -O3 -flto -mtune=generic -march=x86-64 \
                     -funroll-loops -fomit-frame-pointer \
                     -fPIE -fstack-protector-strong -D_FORTIFY_SOURCE=2
    DEBUG_CFLAGS   = -Wall -Wextra -g -O0 \
                     -fsanitize=address,undefined \
                     -fno-omit-frame-pointer
endif

SRCS     = $(wildcard $(SRCDIR)/*.c)
OBJS     = $(patsubst $(SRCDIR)/%.c,$(SRCDIR)/%.o,$(SRCS))

.PHONY: all release debug test chaos clean

# ── Default: release ───────────────────────────────────────────────────

all: release

release: CFLAGS = $(RELEASE_CFLAGS)
release: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# ── Debug with sanitizers ──────────────────────────────────────────────

debug: CFLAGS = $(DEBUG_CFLAGS)
debug: clean-obj $(TARGET)

# ── Unit tests ─────────────────────────────────────────────────────────

$(TESTBIN): $(TESTDIR)/test_runner.c $(TARGET)
	$(CC) $(CFLAGS) $(TESTDIR)/test_runner.c -o $@

test: CFLAGS = $(RELEASE_CFLAGS)
test: $(TARGET) $(TESTBIN)
	./$(TESTBIN)

# ── Chaos / stress tests ───────────────────────────────────────────────

$(CHAOSBIN): $(TESTDIR)/chaos_test.c
	$(CC) $(CFLAGS) $(TESTDIR)/chaos_test.c -o $@

chaos: CFLAGS = $(RELEASE_CFLAGS)
chaos: $(TARGET) $(CHAOSBIN)
	./$(CHAOSBIN)

# ── ASAN on everything ─────────────────────────────────────────────────

test-asan: CFLAGS = $(DEBUG_CFLAGS)
test-asan: clean-obj $(TARGET) $(TESTBIN) $(CHAOSBIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(TESTBIN)
	ASAN_OPTIONS=detect_leaks=1 ./$(CHAOSBIN)

# ── Clean ──────────────────────────────────────────────────────────────

clean:
	rm -f $(SRCDIR)/*.o $(TARGET) $(TESTBIN) $(CHAOSBIN) *.tmp

clean-obj:
	rm -f $(SRCDIR)/*.o
