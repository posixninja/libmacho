/**
 * tests/test_header.c - Unit tests for Mach-O header parsing.
 *
 * Tests macho_header_create(), macho_header_load(), macho_header_free()
 * for both 32-bit and 64-bit Mach-O files.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_framework.h"
#include <macho/macho.h>

/*
 * Minimal 32-bit Mach-O header bytes (little-endian x86).
 * magic=0xFEEDFACE, cputype=7(x86), filetype=2(MH_EXECUTE), ncmds=2.
 */
static unsigned char data_32[] = {
    0xCE, 0xFA, 0xED, 0xFE,  /* magic = MACHO_MAGIC_32 */
    0x07, 0x00, 0x00, 0x00,  /* cputype = CPU_TYPE_X86 */
    0x03, 0x00, 0x00, 0x00,  /* cpusubtype */
    0x02, 0x00, 0x00, 0x00,  /* filetype = MH_EXECUTE */
    0x02, 0x00, 0x00, 0x00,  /* ncmds = 2 */
    0x60, 0x00, 0x00, 0x00,  /* sizeofcmds = 96 */
    0x85, 0x00, 0x21, 0x00,  /* flags */
};

/*
 * Minimal 64-bit Mach-O header bytes (little-endian x86_64).
 * magic=0xFEEDFACF, cputype=0x01000007(x86_64), ncmds=1, reserved=0.
 */
static unsigned char data_64[] = {
    0xCF, 0xFA, 0xED, 0xFE,  /* magic = MACHO_MAGIC_64 */
    0x07, 0x00, 0x00, 0x01,  /* cputype = CPU_TYPE_X86_64 */
    0x03, 0x00, 0x00, 0x80,  /* cpusubtype */
    0x02, 0x00, 0x00, 0x00,  /* filetype = MH_EXECUTE */
    0x01, 0x00, 0x00, 0x00,  /* ncmds = 1 */
    0x48, 0x00, 0x00, 0x00,  /* sizeofcmds = 72 */
    0x00, 0x00, 0x00, 0x00,  /* flags */
    0x00, 0x00, 0x00, 0x00,  /* reserved */
};

static void test_header_create_free(void)
{
    macho_header_t *hdr = macho_header_create();
    TEST_ASSERT_NOT_NULL(hdr, "macho_header_create() returns non-NULL");
    if (hdr) {
        TEST_ASSERT_EQ(hdr->magic, 0u, "new header: magic initialised to zero");
        macho_header_free(hdr);
    }
}

static void test_header_free_null(void)
{
    macho_header_free(NULL);
    TEST_ASSERT(1, "macho_header_free(NULL) does not crash");
}

static void test_header_load_32(void)
{
    macho_t macho;
    memset(&macho, 0, sizeof(macho));
    macho.data   = data_32;
    macho.size   = sizeof(data_32);
    macho.offset = 0;

    macho_header_t *hdr = macho_header_load(&macho);
    TEST_ASSERT_NOT_NULL(hdr, "macho_header_load() returns non-NULL for 32-bit");
    if (hdr) {
        TEST_ASSERT_EQ(hdr->magic,    0xFEEDFACEu, "32-bit magic");
        TEST_ASSERT_EQ(hdr->cputype,  7u,           "cputype = CPU_TYPE_X86");
        TEST_ASSERT_EQ(hdr->filetype, 2u,           "filetype = MH_EXECUTE");
        TEST_ASSERT_EQ(hdr->ncmds,    2u,           "ncmds = 2");
        TEST_ASSERT_EQ(hdr->is_64,    0u,           "is_64 = 0 for 32-bit");
        macho_header_free(hdr);
    }
}

static void test_header_load_64(void)
{
    macho_t macho;
    memset(&macho, 0, sizeof(macho));
    macho.data   = data_64;
    macho.size   = sizeof(data_64);
    macho.offset = 0;

    macho_header_t *hdr = macho_header_load(&macho);
    TEST_ASSERT_NOT_NULL(hdr, "macho_header_load() returns non-NULL for 64-bit");
    if (hdr) {
        TEST_ASSERT_EQ(hdr->magic,  0xFEEDFACFu, "64-bit magic");
        TEST_ASSERT_EQ(hdr->ncmds,  1u,           "ncmds = 1");
        TEST_ASSERT_EQ(hdr->is_64,  1u,           "is_64 = 1 for 64-bit");
        macho_header_free(hdr);
    }
}

static void test_header_load_null(void)
{
    macho_header_t *hdr = macho_header_load(NULL);
    TEST_ASSERT_NULL(hdr, "macho_header_load(NULL) returns NULL");
}

int main(void)
{
    printf("=== Header Tests ===\n");
    RUN_TEST(test_header_create_free);
    RUN_TEST(test_header_free_null);
    RUN_TEST(test_header_load_32);
    RUN_TEST(test_header_load_64);
    RUN_TEST(test_header_load_null);
    return test_report();
}
