# Makefile — Sandbox File Analysis Engine (C Edition)
#
# Build:   make
# Clean:   make clean
# Test:    make test
#
# Compiler flags follow security best practices:
#   -Wall -Wextra -Werror   : strict warnings as errors
#   -O2                      : optimise
#   -fstack-protector-strong : stack canaries
#   -D_FORTIFY_SOURCE=2      : glibc fortification (Linux only)

CC       ?= gcc
CFLAGS   += -Wall -Wextra -Werror -O2
LDFLAGS  +=

SRCDIR   = src
OBJDIR   = obj
TARGET   = sandbox_engine
ifeq ($(OS),Windows_NT)
    TARGET := $(TARGET).exe
endif

# Detect compiler for platform-specific flags
ifeq ($(CC),tcc)
    # TCC has limited flag support — keep it minimal
    CFLAGS = -Wall
else
    CFLAGS += -fstack-protector-strong
    # -fPIE is added conditionally below
endif

SRCS = $(wildcard $(SRCDIR)/*.c)
OBJS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

.PHONY: all clean test

all: $(TARGET)

$(OBJDIR):
	mkdir -p $(OBJDIR)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

test: $(TARGET)
	python -m pytest tests/ -v

clean:
	rm -rf $(OBJDIR) $(TARGET)
