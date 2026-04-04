# Standalone Makefile for libmacho tests
#
# Compiles the library sources directly with stub headers that replace
# libchronic, so no external dependencies are required.
#
# Usage:
#   cd tests/
#   make          # build all test binaries
#   make check    # build and run the full test suite
#   make clean    # remove built binaries

CC      = gcc
CFLAGS  = -Wall -Wextra -g -I../include -I.

SRCDIR  = ../src

LIB_SRCS = \
	$(SRCDIR)/macho.c   \
	$(SRCDIR)/command.c \
	$(SRCDIR)/segment.c \
	$(SRCDIR)/section.c \
	$(SRCDIR)/symtab.c  \
	$(SRCDIR)/symbol.c

TESTS = test_macho test_header test_command test_segment test_symtab

.PHONY: all check run clean

all: $(TESTS)

test_macho: test_macho.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

test_header: test_header.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

test_command: test_command.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

test_segment: test_segment.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

test_symtab: test_symtab.c $(LIB_SRCS)
	$(CC) $(CFLAGS) -o $@ $^

check run: all
	@bash run_tests.sh

clean:
	rm -f $(TESTS) *.o
