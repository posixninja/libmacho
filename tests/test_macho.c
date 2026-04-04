/**
 * tests/test_macho.c - Integration tests for the top-level Mach-O API.
 *
 * Covers macho_create, macho_load, macho_free, macho_lookup, and
 * macho_list_symbols using self-contained binary blobs:
 *
 *  macho32_with_symtab  – 32-bit file with one LC_SYMTAB (symbol "_mysym")
 *  macho32_with_segment – 32-bit file with one LC_SEGMENT ("__TEXT")
 *  macho64_with_segment – 64-bit file with one LC_SEGMENT_64 ("__TEXT")
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_framework.h"
#include <macho/macho.h>

/*
 * Minimal 32-bit Mach-O with LC_SYMTAB and one symbol "_mysym"=0x1234.
 *
 * Layout:
 *   0x00 (28): Mach-O 32-bit header
 *   0x1c (24): LC_SYMTAB  – symoff=0x34 nsyms=1 stroff=0x40 strsize=8
 *   0x34 (12): 32-bit nlist entry – n_strx=1 n_value=0x1234
 *   0x40  (8): string table – '\0' "_mysym\0"
 */
static unsigned char macho32_with_symtab[] = {
    /* Header (28 bytes) */
    0xCE, 0xFA, 0xED, 0xFE,  /* magic = MACHO_MAGIC_32     */
    0x07, 0x00, 0x00, 0x00,  /* cputype = CPU_TYPE_X86     */
    0x03, 0x00, 0x00, 0x00,  /* cpusubtype                 */
    0x02, 0x00, 0x00, 0x00,  /* filetype = MH_EXECUTE      */
    0x01, 0x00, 0x00, 0x00,  /* ncmds = 1                  */
    0x18, 0x00, 0x00, 0x00,  /* sizeofcmds = 24            */
    0x00, 0x00, 0x00, 0x00,  /* flags                      */
    /* LC_SYMTAB (24 bytes) at 0x1c */
    0x02, 0x00, 0x00, 0x00,  /* cmd = LC_SYMTAB (2)        */
    0x18, 0x00, 0x00, 0x00,  /* cmdsize = 24               */
    0x34, 0x00, 0x00, 0x00,  /* symoff = 52 (0x34)         */
    0x01, 0x00, 0x00, 0x00,  /* nsyms = 1                  */
    0x40, 0x00, 0x00, 0x00,  /* stroff = 64 (0x40)         */
    0x08, 0x00, 0x00, 0x00,  /* strsize = 8                */
    /* 32-bit nlist entry (12 bytes) at 0x34 */
    0x01, 0x00, 0x00, 0x00,  /* n_strx = 1                 */
    0x0f,                    /* n_type = N_SECT|N_EXT      */
    0x01,                    /* n_sect = 1                 */
    0x00, 0x00,              /* n_desc = 0                 */
    0x34, 0x12, 0x00, 0x00,  /* n_value = 0x1234           */
    /* String table (8 bytes) at 0x40 */
    0x00,                            /* strtab[0] = '\0'   */
    '_', 'm', 'y', 's', 'y', 'm',   /* strtab[1] = "_mysym" */
    0x00,                            /* NUL terminator     */
};

/*
 * Minimal 32-bit Mach-O with LC_SEGMENT ("__TEXT").
 *
 * Layout:
 *   0x00 (28): 32-bit header
 *   0x1c (56): LC_SEGMENT "__TEXT"
 */
static unsigned char macho32_with_segment[] = {
    /* Header (28 bytes) */
    0xCE, 0xFA, 0xED, 0xFE,
    0x07, 0x00, 0x00, 0x00,
    0x03, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00,  /* ncmds = 1      */
    0x38, 0x00, 0x00, 0x00,  /* sizeofcmds = 56 */
    0x00, 0x00, 0x00, 0x00,
    /* LC_SEGMENT (56 bytes) at 0x1c */
    0x01, 0x00, 0x00, 0x00,                          /* cmd = LC_SEGMENT        */
    0x38, 0x00, 0x00, 0x00,                          /* cmdsize = 56            */
    '_', '_', 'T', 'E', 'X', 'T', 0, 0,             /* segname[16]             */
    0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x10, 0x00, 0x00,                          /* vmaddr   = 0x1000       */
    0x00, 0x10, 0x00, 0x00,                          /* vmsize   = 0x1000       */
    0x00, 0x00, 0x00, 0x00,                          /* fileoff  = 0            */
    0x54, 0x00, 0x00, 0x00,                          /* filesize = 84           */
    0x07, 0x00, 0x00, 0x00,                          /* maxprot  = 7            */
    0x05, 0x00, 0x00, 0x00,                          /* initprot = 5            */
    0x00, 0x00, 0x00, 0x00,                          /* nsects   = 0            */
    0x00, 0x00, 0x00, 0x00,                          /* flags    = 0            */
};

/*
 * Minimal 64-bit Mach-O with LC_SEGMENT_64 ("__TEXT").
 *
 * Layout:
 *   0x00 (32): 64-bit header
 *   0x20 (72): LC_SEGMENT_64 "__TEXT"
 */
static unsigned char macho64_with_segment[] = {
    /* Header (32 bytes) */
    0xCF, 0xFA, 0xED, 0xFE,
    0x07, 0x00, 0x00, 0x01,  /* cputype = CPU_TYPE_X86_64  */
    0x03, 0x00, 0x00, 0x80,  /* cpusubtype                 */
    0x02, 0x00, 0x00, 0x00,  /* filetype = MH_EXECUTE      */
    0x01, 0x00, 0x00, 0x00,  /* ncmds = 1                  */
    0x48, 0x00, 0x00, 0x00,  /* sizeofcmds = 72            */
    0x00, 0x00, 0x00, 0x00,  /* flags                      */
    0x00, 0x00, 0x00, 0x00,  /* reserved                   */
    /* LC_SEGMENT_64 (72 bytes) at 0x20 */
    0x19, 0x00, 0x00, 0x00,                          /* cmd = LC_SEGMENT_64     */
    0x48, 0x00, 0x00, 0x00,                          /* cmdsize = 72            */
    '_', '_', 'T', 'E', 'X', 'T', 0, 0,             /* segname[16]             */
    0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, /* vmaddr  = 0x100000000   */
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* vmsize  = 0x1000        */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* fileoff = 0             */
    0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* filesize = 104          */
    0x07, 0x00, 0x00, 0x00,                          /* maxprot = 7             */
    0x05, 0x00, 0x00, 0x00,                          /* initprot = 5            */
    0x00, 0x00, 0x00, 0x00,                          /* nsects = 0              */
    0x00, 0x00, 0x00, 0x00,                          /* flags = 0               */
};

/* ------------------------------------------------------------------ */

static void test_macho_create_free(void)
{
    macho_t *m = macho_create();
    TEST_ASSERT_NOT_NULL(m, "macho_create() returns non-NULL");
    macho_free(m);
}

static void test_macho_free_null(void)
{
    macho_free(NULL);
    TEST_ASSERT(1, "macho_free(NULL) does not crash");
}

static void test_macho_load_null(void)
{
    macho_t *m = macho_load(NULL, 0);
    TEST_ASSERT_NULL(m, "macho_load(NULL, 0) returns NULL");
}

static void test_macho_load_32_symtab(void)
{
    macho_t *m = macho_load(macho32_with_symtab, sizeof(macho32_with_symtab));
    TEST_ASSERT_NOT_NULL(m, "macho_load() succeeds for 32-bit binary with symtab");
    if (!m) return;
    TEST_ASSERT_NOT_NULL(m->header,          "header is populated");
    TEST_ASSERT_EQ(m->header->is_64,  0u,    "is_64 = 0");
    TEST_ASSERT_EQ(m->command_count,  1u,    "command_count = 1");
    TEST_ASSERT_EQ(m->symtab_count,   1u,    "symtab_count = 1");
    macho_free(m);
}

static void test_macho_load_32_segment(void)
{
    macho_t *m = macho_load(macho32_with_segment, sizeof(macho32_with_segment));
    TEST_ASSERT_NOT_NULL(m, "macho_load() succeeds for 32-bit binary with segment");
    if (!m) return;
    TEST_ASSERT_EQ(m->segment_count, 1u, "segment_count = 1");
    TEST_ASSERT_NOT_NULL(m->segments, "segments array is non-NULL");
    if (m->segments && m->segments[0]) {
        TEST_ASSERT_STREQ(m->segments[0]->name, "__TEXT",
                          "first segment name = __TEXT");
    }
    macho_free(m);
}

static void test_macho_load_64_segment(void)
{
    macho_t *m = macho_load(macho64_with_segment, sizeof(macho64_with_segment));
    TEST_ASSERT_NOT_NULL(m, "macho_load() succeeds for 64-bit binary with segment");
    if (!m) return;
    TEST_ASSERT_EQ(m->header->is_64,  1u,  "is_64 = 1");
    TEST_ASSERT_EQ(m->segment_count,  1u,  "segment_count = 1");
    if (m->segments && m->segments[0]) {
        TEST_ASSERT_STREQ(m->segments[0]->name, "__TEXT",
                          "first segment name = __TEXT");
    }
    macho_free(m);
}

static void test_macho_lookup(void)
{
    macho_t *m = macho_load(macho32_with_symtab, sizeof(macho32_with_symtab));
    TEST_ASSERT_NOT_NULL(m, "macho_load() succeeds for lookup test");
    if (!m) return;

    uint64_t addr = macho_lookup(m, "_mysym");
    TEST_ASSERT_EQ(addr, (uint64_t)0x1234, "lookup('_mysym') = 0x1234");

    uint64_t missing = macho_lookup(m, "_notexist");
    TEST_ASSERT_EQ(missing, (uint64_t)0, "lookup of unknown symbol returns 0");

    macho_free(m);
}

static int _sym_count = 0;
static void _count_sym(const char *name, uint64_t value, void *userdata)
{
    (void)name; (void)value; (void)userdata;
    _sym_count++;
}

static void test_macho_list_symbols(void)
{
    macho_t *m = macho_load(macho32_with_symtab, sizeof(macho32_with_symtab));
    TEST_ASSERT_NOT_NULL(m, "macho_load() succeeds for list_symbols test");
    if (!m) return;

    _sym_count = 0;
    macho_list_symbols(m, _count_sym, NULL);
    TEST_ASSERT_EQ(_sym_count, 1, "macho_list_symbols() enumerates 1 symbol");

    macho_free(m);
}

int main(void)
{
    printf("=== Macho API Tests ===\n");
    RUN_TEST(test_macho_create_free);
    RUN_TEST(test_macho_free_null);
    RUN_TEST(test_macho_load_null);
    RUN_TEST(test_macho_load_32_symtab);
    RUN_TEST(test_macho_load_32_segment);
    RUN_TEST(test_macho_load_64_segment);
    RUN_TEST(test_macho_lookup);
    RUN_TEST(test_macho_list_symbols);
    return test_report();
}
