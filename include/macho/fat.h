/**
 * GreenPois0n Absinthe - macho_fat.h
 */
#ifndef MACHO_FAT_H_
#define MACHO_FAT_H_

#include <stddef.h>
#include <stdint.h>

typedef struct macho_fat_arch_t {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} macho_fat_arch_t;

typedef struct macho_fat_t {
    uint32_t magic;
    uint32_t nfat_arch;
    uint8_t needs_swap;
    macho_fat_arch_t* arches;
} macho_fat_t;

typedef struct macho_fat_input_t {
    const unsigned char* data;
    uint32_t size;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t align;
} macho_fat_input_t;

typedef struct macho_fat_file_input_t {
    const char* path;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t align;
} macho_fat_file_input_t;

int macho_fat_inspect(const unsigned char* data, unsigned int size, macho_fat_t** fat_out);
const macho_fat_arch_t* macho_fat_find_arch(const macho_fat_t* fat, uint32_t cputype, uint32_t cpusubtype);
const macho_fat_arch_t* macho_fat_preferred_arch(const macho_fat_t* fat, const unsigned char* raw_data, unsigned int raw_size);
int macho_fat_extract_arch(const macho_fat_t* fat, const unsigned char* raw_data, unsigned int raw_size, const macho_fat_arch_t* arch, unsigned char** image_data, unsigned int* image_size, uint32_t* image_offset);
int macho_fat_thin_buffer(const unsigned char* raw_data, unsigned int raw_size, uint32_t cputype, uint32_t cpusubtype, unsigned char** out_data, unsigned int* out_size);
int macho_fat_combine_buffers(const macho_fat_input_t* inputs, size_t input_count, unsigned char** out_data, unsigned int* out_size);
int macho_fat_thin_file(const char* src_path, const char* dst_path, uint32_t cputype, uint32_t cpusubtype);
int macho_fat_combine_files(const char* dst_path, const macho_fat_file_input_t* inputs, size_t input_count);
void macho_fat_free(macho_fat_t* fat);

#endif /* MACHO_FAT_H_ */
