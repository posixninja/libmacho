/**
 * tests/test_symtab.c - Unit tests for Mach-O symbol-table parsing.
 *
 * Tests macho_symtab_create/load/free and
 * macho_symtab_cmd_create/load/free for both 32-bit and 64-bit
 * symbol formats (nlist and nlist_64).
 *
 * The test data is a self-contained byte buffer that acts as both
 * the LC_SYMTAB command and the underlying Mach-O data blob:
 *
 *   offset  0: LC_SYMTAB command    (24 bytes)
 *   offset 24: symbol table entries (12 bytes for 32-bit, 16 for 64-bit)
 *   offset 36 / 40: string table    (8 bytes)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_framework.h"
#include <macho/symtab.h>

/*
 * 32-bit symbol table blob:
 *   LC_SYMTAB:  cmd=2 cmdsize=24 symoff=24 nsyms=1 stroff=36 strsize=8
 *   nlist entry: n_strx=1 n_type=0x0f n_sect=1 n_desc=0 n_value=0x1234
 *   string table: '\0' "_foo\0\0\0"
 */
static unsigned char symtab32_data[] = {
    /* LC_SYMTAB (24 bytes) */
    0x02, 0x00, 0x00, 0x00,  /* cmd = LC_SYMTAB (2)     */
    0x18, 0x00, 0x00, 0x00,  /* cmdsize = 24             */
    0x18, 0x00, 0x00, 0x00,  /* symoff  = 24             */
    0x01, 0x00, 0x00, 0x00,  /* nsyms   = 1              */
    0x24, 0x00, 0x00, 0x00,  /* stroff  = 36             */
    0x08, 0x00, 0x00, 0x00,  /* strsize = 8              */
    /* 32-bit nlist entry (12 bytes) at offset 24 */
    0x01, 0x00, 0x00, 0x00,  /* n_strx  = 1              */
    0x0f,                    /* n_type  = N_SECT|N_EXT   */
    0x01,                    /* n_sect  = 1              */
    0x00, 0x00,              /* n_desc  = 0              */
    0x34, 0x12, 0x00, 0x00,  /* n_value = 0x1234 (LE 32) */
    /* string table (8 bytes) at offset 36 */
    0x00,                    /* strtab[0] = '\0'         */
    '_', 'f', 'o', 'o',      /* strtab[1] = "_foo"       */
    0x00, 0x00, 0x00,        /* padding                  */
};

/*
 * 64-bit symbol table blob:
 *   LC_SYMTAB:  cmd=2 cmdsize=24 symoff=24 nsyms=1 stroff=40 strsize=8
 *   nlist_64:   n_strx=1 n_type=0x0f n_sect=1 n_desc=0 n_value=0x12345678
 *   string table: '\0' "_bar\0\0\0"
 */
static unsigned char symtab64_data[] = {
    /* LC_SYMTAB (24 bytes) */
    0x02, 0x00, 0x00, 0x00,  /* cmd = LC_SYMTAB (2)     */
    0x18, 0x00, 0x00, 0x00,  /* cmdsize = 24             */
    0x18, 0x00, 0x00, 0x00,  /* symoff  = 24             */
    0x01, 0x00, 0x00, 0x00,  /* nsyms   = 1              */
    0x28, 0x00, 0x00, 0x00,  /* stroff  = 40             */
    0x08, 0x00, 0x00, 0x00,  /* strsize = 8              */
    /* 64-bit nlist_64 entry (16 bytes) at offset 24 */
    0x01, 0x00, 0x00, 0x00,                          /* n_strx  = 1             */
    0x0f,                                            /* n_type                  */
    0x01,                                            /* n_sect  = 1             */
    0x00, 0x00,                                      /* n_desc  = 0             */
    0x78, 0x56, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, /* n_value = 0x12345678    */
    /* string table (8 bytes) at offset 40 */
    0x00,                    /* strtab[0] = '\0'         */
    '_', 'b', 'a', 'r',      /* strtab[1] = "_bar"       */
    0x00, 0x00, 0x00,        /* padding                  */
};

static void test_symtab_create_free(void)
{
    macho_symtab_t *st = macho_symtab_create();
    TEST_ASSERT_NOT_NULL(st, "macho_symtab_create() returns non-NULL");
    if (st) {
        TEST_ASSERT_EQ(st->nsyms, 0u, "nsyms is 0 on creation");
        macho_symtab_free(st);
    }
}

static void test_symtab_free_null(void)
{
    macho_symtab_free(NULL);
    TEST_ASSERT(1, "macho_symtab_free(NULL) does not crash");
}

static void test_symtab_cmd_create_free(void)
{
    macho_symtab_cmd_t *cmd = macho_symtab_cmd_create();
    TEST_ASSERT_NOT_NULL(cmd, "macho_symtab_cmd_create() returns non-NULL");
    macho_symtab_cmd_free(cmd);
}

static void test_symtab_cmd_load(void)
{
    macho_symtab_cmd_t *cmd = macho_symtab_cmd_load(symtab32_data);
    TEST_ASSERT_NOT_NULL(cmd, "macho_symtab_cmd_load() returns non-NULL");
    if (cmd) {
        TEST_ASSERT_EQ(cmd->cmd,     (uint32_t)0x2, "cmd = LC_SYMTAB");
        TEST_ASSERT_EQ(cmd->nsyms,   1u,            "nsyms = 1");
        TEST_ASSERT_EQ(cmd->symoff,  24u,           "symoff = 24");
        TEST_ASSERT_EQ(cmd->stroff,  36u,           "stroff = 36");
        TEST_ASSERT_EQ(cmd->strsize, 8u,            "strsize = 8");
        macho_symtab_cmd_free(cmd);
    }
}

static void test_symtab_load_32(void)
{
    macho_symtab_t *st = macho_symtab_load(symtab32_data, symtab32_data, 0);
    TEST_ASSERT_NOT_NULL(st, "macho_symtab_load() non-NULL for 32-bit");
    if (!st) return;
    TEST_ASSERT_EQ(st->nsyms,  1u, "nsyms = 1");
    TEST_ASSERT_EQ(st->is_64,  0u, "is_64 = 0");
    TEST_ASSERT_NOT_NULL(st->symbols, "symbols array is non-NULL");
    if (st->symbols) {
        TEST_ASSERT_NOT_NULL(st->symbols[0].n_un.n_name, "symbol 0 has a name");
        if (st->symbols[0].n_un.n_name) {
            TEST_ASSERT_STREQ(st->symbols[0].n_un.n_name, "_foo",
                              "symbol name = _foo");
        }
        TEST_ASSERT_EQ(st->symbols[0].n_value, (uint64_t)0x1234,
                       "n_value = 0x1234");
        TEST_ASSERT_EQ(st->symbols[0].n_type, (uint8_t)0x0f,
                       "n_type = 0x0f");
        TEST_ASSERT_EQ(st->symbols[0].n_sect, (uint8_t)1,
                       "n_sect = 1");
    }
    macho_symtab_free(st);
}

static void test_symtab_load_64(void)
{
    macho_symtab_t *st = macho_symtab_load(symtab64_data, symtab64_data, 1);
    TEST_ASSERT_NOT_NULL(st, "macho_symtab_load() non-NULL for 64-bit");
    if (!st) return;
    TEST_ASSERT_EQ(st->nsyms, 1u, "nsyms = 1");
    TEST_ASSERT_EQ(st->is_64, 1u, "is_64 = 1");
    TEST_ASSERT_NOT_NULL(st->symbols, "symbols array is non-NULL");
    if (st->symbols) {
        TEST_ASSERT_NOT_NULL(st->symbols[0].n_un.n_name, "symbol 0 has a name");
        if (st->symbols[0].n_un.n_name) {
            TEST_ASSERT_STREQ(st->symbols[0].n_un.n_name, "_bar",
                              "symbol name = _bar");
        }
        TEST_ASSERT_EQ(st->symbols[0].n_value, (uint64_t)0x12345678,
                       "n_value = 0x12345678");
    }
    macho_symtab_free(st);
}

static void test_symtab_load_zero_syms(void)
{
    /* A symtab command with nsyms=0 should succeed and have no symbols. */
    static unsigned char empty_cmd[] = {
        0x02, 0x00, 0x00, 0x00,  /* cmd = LC_SYMTAB */
        0x18, 0x00, 0x00, 0x00,  /* cmdsize = 24    */
        0x00, 0x00, 0x00, 0x00,  /* symoff  = 0     */
        0x00, 0x00, 0x00, 0x00,  /* nsyms   = 0     */
        0x00, 0x00, 0x00, 0x00,  /* stroff  = 0     */
        0x00, 0x00, 0x00, 0x00,  /* strsize = 0     */
    };
    macho_symtab_t *st = macho_symtab_load(empty_cmd, empty_cmd, 0);
    TEST_ASSERT_NOT_NULL(st, "macho_symtab_load() handles nsyms=0");
    if (st) {
        TEST_ASSERT_EQ(st->nsyms, 0u,  "nsyms = 0");
        TEST_ASSERT_NULL(st->symbols,   "symbols is NULL when nsyms=0");
        macho_symtab_free(st);
    }
}

int main(void)
{
    printf("=== Symtab Tests ===\n");
    RUN_TEST(test_symtab_create_free);
    RUN_TEST(test_symtab_free_null);
    RUN_TEST(test_symtab_cmd_create_free);
    RUN_TEST(test_symtab_cmd_load);
    RUN_TEST(test_symtab_load_32);
    RUN_TEST(test_symtab_load_64);
    RUN_TEST(test_symtab_load_zero_syms);
    return test_report();
}
