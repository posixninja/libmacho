/**
 * tests/test_segment.c - Unit tests for Mach-O segment parsing.
 *
 * Tests macho_segment_create/load/free and
 * macho_segment_cmd_create/load/free for both 32-bit (LC_SEGMENT)
 * and 64-bit (LC_SEGMENT_64) formats.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_framework.h"
#include <macho/macho.h>

/*
 * 32-bit LC_SEGMENT command (56 bytes).
 * segname="__TEXT", vmaddr=0x1000, vmsize=0x1000, fileoff=0, filesize=84.
 */
static unsigned char seg32_data[] = {
    0x01, 0x00, 0x00, 0x00,                          /* cmd = LC_SEGMENT (1) */
    0x38, 0x00, 0x00, 0x00,                          /* cmdsize = 56         */
    '_', '_', 'T', 'E', 'X', 'T', 0, 0,             /* segname[16]          */
    0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x10, 0x00, 0x00,                          /* vmaddr   = 0x1000    */
    0x00, 0x10, 0x00, 0x00,                          /* vmsize   = 0x1000    */
    0x00, 0x00, 0x00, 0x00,                          /* fileoff  = 0         */
    0x54, 0x00, 0x00, 0x00,                          /* filesize = 84        */
    0x07, 0x00, 0x00, 0x00,                          /* maxprot  = 7         */
    0x05, 0x00, 0x00, 0x00,                          /* initprot = 5         */
    0x00, 0x00, 0x00, 0x00,                          /* nsects   = 0         */
    0x00, 0x00, 0x00, 0x00,                          /* flags    = 0         */
};

/*
 * 64-bit LC_SEGMENT_64 command (72 bytes).
 * segname="__DATA", vmaddr=0x100000000, vmsize=0x1000.
 */
static unsigned char seg64_data[] = {
    0x19, 0x00, 0x00, 0x00,                          /* cmd = LC_SEGMENT_64 (0x19) */
    0x48, 0x00, 0x00, 0x00,                          /* cmdsize = 72               */
    '_', '_', 'D', 'A', 'T', 'A', 0, 0,             /* segname[16]                */
    0, 0, 0, 0, 0, 0, 0, 0,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, /* vmaddr   = 0x100000000     */
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* vmsize   = 0x1000          */
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* fileoff  = 0x1000          */
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* filesize = 0x1000          */
    0x03, 0x00, 0x00, 0x00,                          /* maxprot  = 3 (rw-)         */
    0x03, 0x00, 0x00, 0x00,                          /* initprot = 3 (rw-)         */
    0x00, 0x00, 0x00, 0x00,                          /* nsects   = 0               */
    0x00, 0x00, 0x00, 0x00,                          /* flags    = 0               */
};

static void test_segment_create_free(void)
{
    macho_segment_t *seg = macho_segment_create();
    TEST_ASSERT_NOT_NULL(seg, "macho_segment_create() returns non-NULL");
    macho_segment_free(seg);
}

static void test_segment_free_null(void)
{
    macho_segment_free(NULL);
    TEST_ASSERT(1, "macho_segment_free(NULL) does not crash");
}

static void test_segment_cmd_create_free(void)
{
    macho_segment_cmd_t *cmd = macho_segment_cmd_create();
    TEST_ASSERT_NOT_NULL(cmd, "macho_segment_cmd_create() returns non-NULL");
    macho_segment_cmd_free(cmd);
}

static void test_segment_cmd_load_32(void)
{
    macho_segment_cmd_t *cmd = macho_segment_cmd_load(seg32_data, 0, 0);
    TEST_ASSERT_NOT_NULL(cmd, "macho_segment_cmd_load() non-NULL for 32-bit");
    if (cmd) {
        TEST_ASSERT_EQ(cmd->cmd,     (uint32_t)0x1,  "cmd = LC_SEGMENT");
        TEST_ASSERT_EQ(cmd->cmdsize, 56u,             "cmdsize = 56");
        TEST_ASSERT_STREQ(cmd->segname, "__TEXT",     "segname = __TEXT");
        TEST_ASSERT_EQ(cmd->vmaddr,  (uint64_t)0x1000, "vmaddr = 0x1000");
        TEST_ASSERT_EQ(cmd->filesize,(uint64_t)84,    "filesize = 84");
        TEST_ASSERT_EQ(cmd->is_64,   0u,              "is_64 = 0");
        macho_segment_cmd_free(cmd);
    }
}

static void test_segment_cmd_load_64(void)
{
    macho_segment_cmd_t *cmd = macho_segment_cmd_load(seg64_data, 0, 1);
    TEST_ASSERT_NOT_NULL(cmd, "macho_segment_cmd_load() non-NULL for 64-bit");
    if (cmd) {
        TEST_ASSERT_EQ(cmd->cmd,    (uint32_t)0x19,          "cmd = LC_SEGMENT_64");
        TEST_ASSERT_EQ(cmd->cmdsize, 72u,                     "cmdsize = 72");
        TEST_ASSERT_STREQ(cmd->segname, "__DATA",             "segname = __DATA");
        TEST_ASSERT_EQ(cmd->vmaddr, (uint64_t)0x100000000ULL,"vmaddr = 0x100000000");
        TEST_ASSERT_EQ(cmd->is_64,  1u,                       "is_64 = 1");
        macho_segment_cmd_free(cmd);
    }
}

static void test_segment_load_32(void)
{
    macho_segment_t *seg = macho_segment_load(seg32_data, 0, 0);
    TEST_ASSERT_NOT_NULL(seg, "macho_segment_load() non-NULL for 32-bit");
    if (seg) {
        TEST_ASSERT_NOT_NULL(seg->name, "segment name is set");
        if (seg->name) {
            TEST_ASSERT_STREQ(seg->name, "__TEXT", "segment name = __TEXT");
        }
        TEST_ASSERT_EQ(seg->address, (uint64_t)0x1000, "address = 0x1000");
        TEST_ASSERT_EQ(seg->is_64,   0u,               "is_64 = 0");
        macho_segment_free(seg);
    }
}

static void test_segment_load_64(void)
{
    macho_segment_t *seg = macho_segment_load(seg64_data, 0, 1);
    TEST_ASSERT_NOT_NULL(seg, "macho_segment_load() non-NULL for 64-bit");
    if (seg) {
        TEST_ASSERT_STREQ(seg->name, "__DATA", "segment name = __DATA");
        TEST_ASSERT_EQ(seg->is_64, 1u, "is_64 = 1");
        macho_segment_free(seg);
    }
}

static void test_segments_create_free(void)
{
    macho_segment_t **segs = macho_segments_create(4);
    TEST_ASSERT_NOT_NULL(segs, "macho_segments_create(4) returns non-NULL");
    if (segs) {
        TEST_ASSERT_NULL(segs[0], "slot 0 is NULL (array is zeroed)");
        TEST_ASSERT_NULL(segs[4], "sentinel slot is NULL");
        macho_segments_free(segs);
    }
}

int main(void)
{
    printf("=== Segment Tests ===\n");
    RUN_TEST(test_segment_create_free);
    RUN_TEST(test_segment_free_null);
    RUN_TEST(test_segment_cmd_create_free);
    RUN_TEST(test_segment_cmd_load_32);
    RUN_TEST(test_segment_cmd_load_64);
    RUN_TEST(test_segment_load_32);
    RUN_TEST(test_segment_load_64);
    RUN_TEST(test_segments_create_free);
    return test_report();
}
