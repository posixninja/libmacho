/**
 * GreenPois0n Absinthe - macho_arch.h
 *
 * Abstraction helpers to unify 32-bit and 64-bit Mach-O parsing.
 */
#ifndef MACHO_ARCH_H_
#define MACHO_ARCH_H_

#include <stdint.h>

struct macho_header_t;
struct macho_segment_cmd_t;
struct macho_nlist_t;

typedef void (*macho_header_reader_t)(struct macho_header_t* header, const unsigned char* data);
typedef void (*macho_segment_reader_t)(struct macho_segment_cmd_t* cmd, const unsigned char* data);
typedef void (*macho_nlist_reader_t)(struct macho_nlist_t* dest, const unsigned char* src);

typedef struct macho_arch_ops_t {
    uint8_t is_64;
    uint8_t pointer_width;
    uint32_t segment_command;
    uint32_t header_size;
    uint32_t segment_command_size;
    uint32_t nlist_entry_size;
    macho_header_reader_t header_reader;
    macho_segment_reader_t segment_reader;
    macho_nlist_reader_t nlist_reader;
} macho_arch_ops_t;

const macho_arch_ops_t* macho_arch_ops_for_magic(uint32_t magic);
const macho_arch_ops_t* macho_arch_ops_for_flag(uint8_t is_64);

#endif /* MACHO_ARCH_H_ */
