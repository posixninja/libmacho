/**
 * GreenPois0n Absinthe - macho_fat.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <chronic/chronic.h>

#include <macho/macho.h>
#include <macho/fat.h>

typedef struct macho_fat_header_t {
    uint32_t magic;
    uint32_t nfat_arch;
} macho_fat_header_t;

typedef struct macho_fat_arch_disk_t {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} macho_fat_arch_disk_t;

static uint32_t macho_swap32(uint32_t value) {
    return ((value & 0x000000FFU) << 24) |
           ((value & 0x0000FF00U) << 8) |
           ((value & 0x00FF0000U) >> 8) |
           ((value & 0xFF000000U) >> 24);
}

static unsigned char* macho_duplicate_slice(const unsigned char* data, uint32_t size) {
    unsigned char* copy = (unsigned char*) malloc(size);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, data, size);
    return copy;
}

static uint32_t macho_align_pow2(uint32_t value, uint32_t align_pow) {
    if (align_pow == 0) {
        return value;
    }
    uint32_t align = 1U << align_pow;
    uint32_t mask = align - 1;
    return (value + mask) & ~mask;
}

int macho_fat_inspect(const unsigned char* data, unsigned int size, macho_fat_t** fat_out) {
    if ((fat_out == NULL) || (data == NULL)) {
        return -1;
    }
    *fat_out = NULL;
    if (size < sizeof(uint32_t)) {
        return 0;
    }

    uint32_t magic = 0;
    memcpy(&magic, data, sizeof(uint32_t));
    if ((magic != MACHO_FAT_MAGIC) && (magic != MACHO_FAT_CIGAM)) {
        return 0;
    }

    if (size < sizeof(macho_fat_header_t)) {
        return -1;
    }

    macho_fat_header_t header = { 0 };
    memcpy(&header, data, sizeof(header));

    uint8_t needs_swap = (magic == MACHO_FAT_CIGAM);
    uint32_t arch_count = needs_swap ? macho_swap32(header.nfat_arch) : header.nfat_arch;
    if (arch_count == 0) {
        return -1;
    }

    size_t directory_size = sizeof(header) + (size_t) arch_count * sizeof(macho_fat_arch_disk_t);
    if (size < directory_size) {
        return -1;
    }

    macho_fat_t* fat = (macho_fat_t*) calloc(1u, sizeof(macho_fat_t));
    if (fat == NULL) {
        return -1;
    }

    fat->magic = magic;
    fat->nfat_arch = arch_count;
    fat->needs_swap = needs_swap;
    fat->arches = (macho_fat_arch_t*) calloc(arch_count, sizeof(macho_fat_arch_t));
    if (fat->arches == NULL) {
        free(fat);
        return -1;
    }

    unsigned int i;
    const unsigned char* arch_ptr = data + sizeof(header);
    for (i = 0; i < arch_count; i++) {
        macho_fat_arch_disk_t disk = { 0 };
        memcpy(&disk, arch_ptr + (i * sizeof(macho_fat_arch_disk_t)), sizeof(disk));
        if (needs_swap) {
            disk.cputype = macho_swap32(disk.cputype);
            disk.cpusubtype = macho_swap32(disk.cpusubtype);
            disk.offset = macho_swap32(disk.offset);
            disk.size = macho_swap32(disk.size);
            disk.align = macho_swap32(disk.align);
        }
        fat->arches[i].cputype = disk.cputype;
        fat->arches[i].cpusubtype = disk.cpusubtype;
        fat->arches[i].offset = disk.offset;
        fat->arches[i].size = disk.size;
        fat->arches[i].align = disk.align;
    }

    *fat_out = fat;
    return 1;
}

const macho_fat_arch_t* macho_fat_find_arch(const macho_fat_t* fat, uint32_t cputype, uint32_t cpusubtype) {
    if ((fat == NULL) || (fat->arches == NULL)) {
        return NULL;
    }

    unsigned int i;
    for (i = 0; i < fat->nfat_arch; i++) {
        const macho_fat_arch_t* arch = &fat->arches[i];
        if ((arch->cputype == cputype) && (arch->cpusubtype == cpusubtype)) {
            return arch;
        }
        if ((arch->cputype == cputype) && (cpusubtype == 0)) {
            return arch;
        }
    }
    return NULL;
}

const macho_fat_arch_t* macho_fat_preferred_arch(const macho_fat_t* fat, const unsigned char* raw_data, unsigned int raw_size) {
    if ((fat == NULL) || (fat->arches == NULL)) {
        return NULL;
    }

    unsigned int i;
    for (i = 0; i < fat->nfat_arch; i++) {
        const macho_fat_arch_t* arch = &fat->arches[i];
        if ((arch->offset + sizeof(uint32_t)) > raw_size) {
            continue;
        }
        uint32_t magic = 0;
        memcpy(&magic, raw_data + arch->offset, sizeof(uint32_t));
        if ((magic == MACHO_MAGIC_64) || (magic == MACHO_CIGAM_64)) {
            return arch;
        }
    }
    return &fat->arches[0];
}

int macho_fat_extract_arch(const macho_fat_t* fat, const unsigned char* raw_data, unsigned int raw_size, const macho_fat_arch_t* arch, unsigned char** image_data, unsigned int* image_size, uint32_t* image_offset) {
    if ((fat == NULL) || (arch == NULL) || (raw_data == NULL) || (image_data == NULL) || (image_size == NULL)) {
        return -1;
    }
    if ((arch->offset >= raw_size) || (arch->size == 0) || (arch->size > (raw_size - arch->offset))) {
        return -1;
    }

    *image_data = (unsigned char*) (raw_data + arch->offset);
    *image_size = arch->size;
    if (image_offset) {
        *image_offset = arch->offset;
    }
    return 0;
}

int macho_fat_thin_buffer(const unsigned char* raw_data, unsigned int raw_size, uint32_t cputype, uint32_t cpusubtype, unsigned char** out_data, unsigned int* out_size) {
    if ((raw_data == NULL) || (out_data == NULL) || (out_size == NULL)) {
        return -1;
    }

    macho_fat_t* fat = NULL;
    int ret = macho_fat_inspect(raw_data, raw_size, &fat);
    if (ret <= 0) {
        return -1;
    }

    const macho_fat_arch_t* arch = macho_fat_find_arch(fat, cputype, cpusubtype);
    if (arch == NULL) {
        macho_fat_free(fat);
        return -1;
    }

    if ((arch->offset >= raw_size) || (arch->size == 0) || (arch->size > (raw_size - arch->offset))) {
        macho_fat_free(fat);
        return -1;
    }

    unsigned char* copy = macho_duplicate_slice(raw_data + arch->offset, arch->size);
    if (copy == NULL) {
        macho_fat_free(fat);
        return -1;
    }

    *out_data = copy;
    *out_size = arch->size;
    macho_fat_free(fat);
    return 0;
}

static int macho_write_file(const char* path, const unsigned char* data, unsigned int size) {
    if ((path == NULL) || (data == NULL)) {
        return -1;
    }
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }
    size_t written = fwrite(data, 1, size, fp);
    fclose(fp);
    return (written == size) ? 0 : -1;
}

static int macho_read_file(const char* path, unsigned char** data_out, unsigned int* size_out) {
    if ((path == NULL) || (data_out == NULL) || (size_out == NULL)) {
        return -1;
    }
    unsigned char* data = NULL;
    unsigned int size = 0;
    if (file_read(path, &data, &size) < 0) {
        return -1;
    }
    *data_out = data;
    *size_out = size;
    return 0;
}

int macho_fat_thin_file(const char* src_path, const char* dst_path, uint32_t cputype, uint32_t cpusubtype) {
    if ((src_path == NULL) || (dst_path == NULL)) {
        return -1;
    }

    unsigned char* raw = NULL;
    unsigned int raw_size = 0;
    if (macho_read_file(src_path, &raw, &raw_size) < 0) {
        return -1;
    }

    unsigned char* slice = NULL;
    unsigned int slice_size = 0;
    int ret = macho_fat_thin_buffer(raw, raw_size, cputype, cpusubtype, &slice, &slice_size);
    if (ret < 0) {
        free(raw);
        return -1;
    }

    ret = macho_write_file(dst_path, slice, slice_size);
    free(slice);
    free(raw);
    return ret;
}

int macho_fat_combine_buffers(const macho_fat_input_t* inputs, size_t input_count, unsigned char** out_data, unsigned int* out_size) {
    if ((inputs == NULL) || (input_count == 0) || (out_data == NULL) || (out_size == NULL)) {
        return -1;
    }

	size_t i;
	for (i = 0; i < input_count; i++) {
		if ((inputs[i].data == NULL) || (inputs[i].size == 0)) {
			return -1;
		}
	}

	size_t header_size = sizeof(macho_fat_header_t) + input_count * sizeof(macho_fat_arch_disk_t);
    uint32_t payload_offset = (uint32_t) header_size;
    for (i = 0; i < input_count; i++) {
        uint32_t align_exp = inputs[i].align ? inputs[i].align : 12;
        payload_offset = macho_align_pow2(payload_offset, align_exp);
        payload_offset += inputs[i].size;
    }

    unsigned char* buffer = (unsigned char*) malloc(payload_offset);
    if (buffer == NULL) {
        return -1;
    }
    memset(buffer, 0, payload_offset);

    macho_fat_header_t header = {
        .magic = MACHO_FAT_MAGIC,
        .nfat_arch = (uint32_t) input_count,
    };
    memcpy(buffer, &header, sizeof(header));

    uint32_t current_offset = (uint32_t) header_size;
    unsigned char* arch_ptr = buffer + sizeof(header);
    for (i = 0; i < input_count; i++) {
        uint32_t align_exp = inputs[i].align ? inputs[i].align : 12;
        current_offset = macho_align_pow2(current_offset, align_exp);
        macho_fat_arch_disk_t disk = {
            .cputype = inputs[i].cputype,
            .cpusubtype = inputs[i].cpusubtype,
            .offset = current_offset,
            .size = inputs[i].size,
            .align = align_exp,
        };
        memcpy(arch_ptr + (i * sizeof(macho_fat_arch_disk_t)), &disk, sizeof(disk));
        memcpy(buffer + current_offset, inputs[i].data, inputs[i].size);
        current_offset += inputs[i].size;
    }

    *out_data = buffer;
    *out_size = current_offset;
    return 0;
}

int macho_fat_combine_files(const char* dst_path, const macho_fat_file_input_t* inputs, size_t input_count) {
    if ((dst_path == NULL) || (inputs == NULL) || (input_count == 0)) {
        return -1;
    }

    macho_fat_input_t* buffers = (macho_fat_input_t*) calloc(input_count, sizeof(macho_fat_input_t));
    if (buffers == NULL) {
        return -1;
    }

    size_t i;
    for (i = 0; i < input_count; i++) {
        if (macho_read_file(inputs[i].path, (unsigned char**) &buffers[i].data, &buffers[i].size) < 0) {
            size_t j;
            for (j = 0; j < i; j++) {
                free((void*) buffers[j].data);
            }
            free(buffers);
            return -1;
        }
        buffers[i].cputype = inputs[i].cputype;
        buffers[i].cpusubtype = inputs[i].cpusubtype;
        buffers[i].align = inputs[i].align;
    }

    unsigned char* combined = NULL;
    unsigned int combined_size = 0;
    int ret = macho_fat_combine_buffers(buffers, input_count, &combined, &combined_size);

    for (i = 0; i < input_count; i++) {
        free((void*) buffers[i].data);
    }
    free(buffers);

    if (ret < 0) {
        return -1;
    }

    ret = macho_write_file(dst_path, combined, combined_size);
    free(combined);
    return ret;
}

void macho_fat_free(macho_fat_t* fat) {
    if (fat) {
        if (fat->arches) {
            free(fat->arches);
        }
        free(fat);
    }
}
