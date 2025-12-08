/**
 * GreenPois0n Absinthe - macho_arch.c
 */
#include <stdlib.h>
#include <string.h>

#include <macho/macho.h>
#include <macho/segment.h>
#include <macho/symtab.h>
#include <macho/arch.h>

/* Disk representations */
typedef struct macho_disk_header32_t {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} macho_disk_header32_t;

typedef struct macho_disk_header64_t {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
} macho_disk_header64_t;

typedef struct macho_segment_cmd32_disk_t {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint32_t vmaddr;
    uint32_t vmsize;
    uint32_t fileoff;
    uint32_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment_cmd32_disk_t;

typedef struct macho_segment_cmd64_disk_t {
    uint32_t cmd;
    uint32_t cmdsize;
    char segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment_cmd64_disk_t;

typedef struct macho_nlist32_disk_t {
    union {
        int32_t n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    int16_t n_desc;
    uint32_t n_value;
} macho_nlist32_disk_t;

typedef struct macho_nlist64_disk_t {
    union {
        int32_t n_strx;
    } n_un;
    uint8_t n_type;
    uint8_t n_sect;
    int16_t n_desc;
    uint64_t n_value;
} macho_nlist64_disk_t;

static void macho_read_header32(struct macho_header_t* header, const unsigned char* data) {
    macho_disk_header32_t disk = { 0 };
    memcpy(&disk, data, sizeof(disk));
    header->magic = disk.magic;
    header->cputype = disk.cputype;
    header->cpusubtype = disk.cpusubtype;
    header->filetype = disk.filetype;
    header->ncmds = disk.ncmds;
    header->sizeofcmds = disk.sizeofcmds;
    header->flags = disk.flags;
    header->reserved = 0;
    header->is_64 = 0;
}

static void macho_read_header64(struct macho_header_t* header, const unsigned char* data) {
    macho_disk_header64_t disk = { 0 };
    memcpy(&disk, data, sizeof(disk));
    header->magic = disk.magic;
    header->cputype = disk.cputype;
    header->cpusubtype = disk.cpusubtype;
    header->filetype = disk.filetype;
    header->ncmds = disk.ncmds;
    header->sizeofcmds = disk.sizeofcmds;
    header->flags = disk.flags;
    header->reserved = disk.reserved;
    header->is_64 = 1;
}

static void macho_read_segment32(struct macho_segment_cmd_t* cmd, const unsigned char* data) {
    macho_segment_cmd32_disk_t disk = { 0 };
    memcpy(&disk, data, sizeof(disk));
    cmd->cmd = disk.cmd;
    cmd->cmdsize = disk.cmdsize;
    memcpy(cmd->segname, disk.segname, sizeof(disk.segname));
    cmd->segname[sizeof(cmd->segname) - 1] = '\0';
    cmd->vmaddr = disk.vmaddr;
    cmd->vmsize = disk.vmsize;
    cmd->fileoff = disk.fileoff;
    cmd->filesize = disk.filesize;
    cmd->maxprot = disk.maxprot;
    cmd->initprot = disk.initprot;
    cmd->nsects = disk.nsects;
    cmd->flags = disk.flags;
    cmd->is_64 = 0;
}

static void macho_read_segment64(struct macho_segment_cmd_t* cmd, const unsigned char* data) {
    macho_segment_cmd64_disk_t disk = { 0 };
    memcpy(&disk, data, sizeof(disk));
    cmd->cmd = disk.cmd;
    cmd->cmdsize = disk.cmdsize;
    memcpy(cmd->segname, disk.segname, sizeof(disk.segname));
    cmd->segname[sizeof(cmd->segname) - 1] = '\0';
    cmd->vmaddr = disk.vmaddr;
    cmd->vmsize = disk.vmsize;
    cmd->fileoff = disk.fileoff;
    cmd->filesize = disk.filesize;
    cmd->maxprot = disk.maxprot;
    cmd->initprot = disk.initprot;
    cmd->nsects = disk.nsects;
    cmd->flags = disk.flags;
    cmd->is_64 = 1;
}

static void macho_read_nlist32(struct macho_nlist_t* dest, const unsigned char* src) {
    macho_nlist32_disk_t disk = { 0 };
    memcpy(&disk, src, sizeof(disk));
    dest->n_un.n_strx = disk.n_un.n_strx;
    dest->n_type = disk.n_type;
    dest->n_sect = disk.n_sect;
    dest->n_desc = disk.n_desc;
    dest->n_value = disk.n_value;
}

static void macho_read_nlist64(struct macho_nlist_t* dest, const unsigned char* src) {
    macho_nlist64_disk_t disk = { 0 };
    memcpy(&disk, src, sizeof(disk));
    dest->n_un.n_strx = disk.n_un.n_strx;
    dest->n_type = disk.n_type;
    dest->n_sect = disk.n_sect;
    dest->n_desc = disk.n_desc;
    dest->n_value = disk.n_value;
}

static const macho_arch_ops_t g_arch32 = {
    .is_64 = 0,
    .pointer_width = 4,
    .segment_command = MACHO_CMD_SEGMENT,
    .header_size = sizeof(macho_disk_header32_t),
    .segment_command_size = sizeof(macho_segment_cmd32_disk_t),
    .nlist_entry_size = sizeof(macho_nlist32_disk_t),
    .header_reader = macho_read_header32,
    .segment_reader = macho_read_segment32,
    .nlist_reader = macho_read_nlist32,
};

static const macho_arch_ops_t g_arch64 = {
    .is_64 = 1,
    .pointer_width = 8,
    .segment_command = MACHO_CMD_SEGMENT_64,
    .header_size = sizeof(macho_disk_header64_t),
    .segment_command_size = sizeof(macho_segment_cmd64_disk_t),
    .nlist_entry_size = sizeof(macho_nlist64_disk_t),
    .header_reader = macho_read_header64,
    .segment_reader = macho_read_segment64,
    .nlist_reader = macho_read_nlist64,
};

const macho_arch_ops_t* macho_arch_ops_for_magic(uint32_t magic) {
    if ((magic == MACHO_MAGIC_64) || (magic == MACHO_CIGAM_64)) {
        return &g_arch64;
    }
    return &g_arch32;
}

const macho_arch_ops_t* macho_arch_ops_for_flag(uint8_t is_64) {
    return is_64 ? &g_arch64 : &g_arch32;
}
