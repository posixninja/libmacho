/**
 * tests/test_command.c - Unit tests for Mach-O load-command parsing.
 *
 * Tests macho_command_create/load/free and macho_command_info_create/load/free,
 * as well as the bulk macho_commands_create/free helpers.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "test_framework.h"
#include <macho/macho.h>

/* Raw LC_SEGMENT command (first 8 bytes: cmd + cmdsize). */
static unsigned char segment_cmd[] = {
    0x01, 0x00, 0x00, 0x00,  /* cmd     = MACHO_CMD_SEGMENT (1) */
    0x38, 0x00, 0x00, 0x00,  /* cmdsize = 56                    */
};

/* Raw LC_SYMTAB command bytes. */
static unsigned char symtab_cmd[] = {
    0x02, 0x00, 0x00, 0x00,  /* cmd     = MACHO_CMD_SYMTAB (2) */
    0x18, 0x00, 0x00, 0x00,  /* cmdsize = 24                   */
};

/* Raw LC_LOAD_DYLIB command bytes. */
static unsigned char dylib_cmd[] = {
    0x0C, 0x00, 0x00, 0x00,  /* cmd     = MACHO_CMD_LOAD_DYLIB (12) */
    0x38, 0x00, 0x00, 0x00,  /* cmdsize = 56                        */
};

static void test_command_create_free(void)
{
    macho_command_t *cmd = macho_command_create();
    TEST_ASSERT_NOT_NULL(cmd, "macho_command_create() returns non-NULL");
    macho_command_free(cmd);
}

static void test_command_free_null(void)
{
    macho_command_free(NULL);
    TEST_ASSERT(1, "macho_command_free(NULL) does not crash");
}

static void test_command_info_create_free(void)
{
    macho_command_info_t *info = macho_command_info_create();
    TEST_ASSERT_NOT_NULL(info, "macho_command_info_create() returns non-NULL");
    macho_command_info_free(info);
}

static void test_command_info_load_segment(void)
{
    macho_command_info_t *info = macho_command_info_load(segment_cmd, 0);
    TEST_ASSERT_NOT_NULL(info, "macho_command_info_load() non-NULL for LC_SEGMENT");
    if (info) {
        TEST_ASSERT_EQ(info->cmd,     (uint32_t)MACHO_CMD_SEGMENT, "cmd = MACHO_CMD_SEGMENT");
        TEST_ASSERT_EQ(info->cmdsize, 56u,                          "cmdsize = 56");
        macho_command_info_free(info);
    }
}

static void test_command_info_load_symtab(void)
{
    macho_command_info_t *info = macho_command_info_load(symtab_cmd, 0);
    TEST_ASSERT_NOT_NULL(info, "macho_command_info_load() non-NULL for LC_SYMTAB");
    if (info) {
        TEST_ASSERT_EQ(info->cmd,     (uint32_t)MACHO_CMD_SYMTAB, "cmd = MACHO_CMD_SYMTAB");
        TEST_ASSERT_EQ(info->cmdsize, 24u,                         "cmdsize = 24");
        macho_command_info_free(info);
    }
}

static void test_command_load_segment(void)
{
    macho_command_t *cmd = macho_command_load(segment_cmd, 0);
    TEST_ASSERT_NOT_NULL(cmd, "macho_command_load() non-NULL for LC_SEGMENT");
    if (cmd) {
        TEST_ASSERT_NOT_NULL(cmd->info, "command->info is non-NULL");
        if (cmd->info) {
            TEST_ASSERT_EQ(cmd->info->cmd, (uint32_t)MACHO_CMD_SEGMENT,
                           "info->cmd = MACHO_CMD_SEGMENT");
        }
        TEST_ASSERT_EQ(cmd->size,   56u, "command size = 56");
        TEST_ASSERT_EQ(cmd->offset, 0u,  "command offset = 0");
        macho_command_free(cmd);
    }
}

static void test_command_load_dylib(void)
{
    macho_command_t *cmd = macho_command_load(dylib_cmd, 0);
    TEST_ASSERT_NOT_NULL(cmd, "macho_command_load() non-NULL for LC_LOAD_DYLIB");
    if (cmd) {
        TEST_ASSERT_EQ(cmd->info->cmd, (uint32_t)MACHO_CMD_LOAD_DYLIB,
                       "info->cmd = MACHO_CMD_LOAD_DYLIB");
        TEST_ASSERT_EQ(cmd->size, 56u, "command size = 56");
        macho_command_free(cmd);
    }
}

static void test_commands_create_free(void)
{
    macho_command_t **cmds = macho_commands_create(3);
    TEST_ASSERT_NOT_NULL(cmds, "macho_commands_create(3) returns non-NULL");
    if (cmds) {
        TEST_ASSERT_NULL(cmds[0], "slot 0 is NULL (array is zeroed)");
        TEST_ASSERT_NULL(cmds[3], "sentinel slot is NULL");
        macho_commands_free(cmds);
    }
}

int main(void)
{
    printf("=== Command Tests ===\n");
    RUN_TEST(test_command_create_free);
    RUN_TEST(test_command_free_null);
    RUN_TEST(test_command_info_create_free);
    RUN_TEST(test_command_info_load_segment);
    RUN_TEST(test_command_info_load_symtab);
    RUN_TEST(test_command_load_segment);
    RUN_TEST(test_command_load_dylib);
    RUN_TEST(test_commands_create_free);
    return test_report();
}
