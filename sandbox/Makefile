# Makefile — Sandbox File Analysis Engine (C Only)
#
# Build:   make
# Test:    make test
# Clean:   make clean

CC       ?= gcc
CFLAGS   += -Wall -Wextra -Werror -O2 -fstack-protector-strong

SRCDIR   = src
TESTDIR  = tests
BINDIR   = .
TARGET   = sandbox_engine
TESTBIN  = test_runner
ifeq ($(OS),Windows_NT)
    TARGET := $(TARGET).exe
    TESTBIN := $(TESTBIN).exe
endif

# Detect TCC (limited flags)
ifeq ($(CC),tcc)
    CFLAGS = -Wall
endif

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(SRCDIR)/%.o,$(SRCS))

.PHONY: all clean test

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(SRCDIR)/%.o: $(SRCDIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Test runner
$(TESTBIN): $(TESTDIR)/test_runner.c $(TARGET)
	$(CC) $(CFLAGS) $(TESTDIR)/test_runner.c -o $@

test: $(TARGET) $(TESTBIN)
	./$(TESTBIN)

clean:
	rm -f $(SRCDIR)/*.o $(TARGET) $(TESTBIN) *.tmp
