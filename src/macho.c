/**
 * GreenPois0n Absinthe - mb2.h
 * Copyright (C) 2010 Chronic-Dev Team
 * Copyright (C) 2010 Joshua Hill
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 **/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <chronic/chronic.h>

#include <macho/macho.h>
#include <macho/symtab.h>

static void macho_reset_parsed_state(macho_t* macho) {
	if (macho == NULL) {
		return;
	}
	if (macho->header) {
		macho_header_free(macho->header);
		macho->header = NULL;
	}
	if (macho->commands) {
		macho_commands_free(macho->commands);
		macho->commands = NULL;
	}
	if (macho->segments) {
		macho_segments_free(macho->segments);
		macho->segments = NULL;
	}
	if (macho->symtabs) {
		macho_symtabs_free(macho->symtabs);
		macho->symtabs = NULL;
	}
	macho->command_count = 0;
	macho->segment_count = 0;
	macho->symtab_count = 0;
	macho->arch_ops = NULL;
}

static int macho_parse_current_image(macho_t* macho);

static int macho_prepare_image(macho_t* macho, unsigned char* image_data, unsigned int image_size,
		uint32_t image_offset, const macho_fat_arch_t* slice) {
	if ((macho == NULL) || (image_data == NULL) || (image_size == 0)) {
		return -1;
	}

	macho_reset_parsed_state(macho);
	macho->data = image_data;
	macho->size = image_size;
	macho->image_offset = image_offset;
	macho->active_slice = slice;
	macho->offset = 0;

	return macho_parse_current_image(macho);
}

static int macho_parse_current_image(macho_t* macho) {
	if ((macho == NULL) || (macho->data == NULL)) {
		return -1;
	}

	macho->header = macho_header_load(macho);
	if (macho->header == NULL) {
		macho_reset_parsed_state(macho);
		return -1;
	}

	macho->command_count = macho->header->ncmds;
	macho->commands = macho_commands_load(macho);
	if (macho->commands == NULL) {
		error("Unable to parse Mach-O load commands\n");
		macho_reset_parsed_state(macho);
		return -1;
	}

	uint32_t seg_count = 0;
	uint32_t symtab_count = 0;
	uint32_t unk_count = 0;
	int i;
	for (i = 0; i < (int) macho->command_count; i++) {
		switch (macho->commands[i]->info->cmd) {
		case MACHO_CMD_SEGMENT:
		case MACHO_CMD_SEGMENT_64:
			seg_count++;
			break;
		case MACHO_CMD_SYMTAB:
			symtab_count++;
			break;
		default:
			unk_count++;
			break;
		}
	}

	macho->segments = macho_segments_create(seg_count);
	if ((seg_count > 0) && (macho->segments == NULL)) {
		error("Unable to allocate segment storage\n");
		macho_reset_parsed_state(macho);
		return -1;
	}
	macho->segment_count = 0;
	macho->symtabs = macho_symtabs_create(symtab_count);
	if ((symtab_count > 0) && (macho->symtabs == NULL)) {
		error("Unable to allocate symtab storage\n");
		macho_reset_parsed_state(macho);
		return -1;
	}
	macho->symtab_count = 0;

	if (unk_count > 0) {
		error("WARNING: %d unhandled Mach-O Commands\n", unk_count);
	}

	for (i = 0; i < (int) macho->command_count; i++) {
		if (macho_handle_command(macho, macho->commands[i]) < 0) {
			error("Unable to handle Mach-O command at index %d\n", i);
		}
	}

	return 0;
}

/*
 * Mach-O Functions
 */
macho_t* macho_create() {
	macho_t* macho = (macho_t*) malloc(sizeof(macho_t));
	if (macho) {
		memset(macho, '\0', sizeof(macho));
	}
	return macho;
}

macho_t* macho_load(unsigned char* data, unsigned int size) {
	if ((data == NULL) || (size == 0)) {
		return NULL;
	}

	macho_t* macho = macho_create();
	if (macho == NULL) {
		return NULL;
	}

	macho->raw_data = data;
	macho->raw_size = size;
	macho->slice_count = 0;
	macho->is_fat = 0;
	macho->fat = NULL;
	macho->active_slice = NULL;

	macho_fat_t* fat = NULL;
	int fat_state = macho_fat_inspect(data, size, &fat);
	if (fat_state < 0) {
		error("Unable to parse Mach-O fat header\n");
		macho_free(macho);
		return NULL;
	}

	if (fat_state > 0) {
		macho->is_fat = 1;
		macho->fat = fat;
		macho->slice_count = fat->nfat_arch;
		const macho_fat_arch_t* preferred = macho_fat_preferred_arch(fat, data, size);
		if (preferred == NULL) {
			error("Unable to locate a valid architecture slice in fat binary\n");
			macho_free(macho);
			return NULL;
		}
		if ((preferred->offset >= size) || (preferred->size == 0) ||
				(preferred->size > (size - preferred->offset))) {
			error("Preferred architecture slice truncated\n");
			macho_free(macho);
			return NULL;
		}
		if (macho_prepare_image(macho, data + preferred->offset, preferred->size,
				preferred->offset, preferred) < 0) {
			error("Unable to parse preferred Mach-O slice\n");
			macho_free(macho);
			return NULL;
		}
	} else {
		if (macho_prepare_image(macho, data, size, 0, NULL) < 0) {
			error("Unable to parse Mach-O image\n");
			macho_free(macho);
			return NULL;
		}
	}

	return macho;
}

macho_t* macho_open(const char* path) {
	int err = 0;
	macho_t* macho = NULL;
	unsigned int size = 0;
	unsigned char* data = NULL;

	if (path) {
		//debug("Reading Mach-O file from path\n");
		err = file_read(path, &data, &size);
		if (err < 0) {
			error("Unable to read Mach-O file\n");
			macho_free(macho);
			return NULL;
		}

		//debug("Creating Mach-O object from file\n");
		macho = macho_load(data, size);
		if (macho == NULL) {
			error("Unable to load Mach-O file\n");
			return NULL;
		}
	}
	return macho;
}

uint64_t macho_lookup(macho_t* macho, const char* sym) {
	int i = 0;
	int j = 0;
	macho_nlist_t* nl = NULL;
	macho_symtab_t* symtab = NULL;

	if ((macho == NULL) || (sym == NULL) || (macho->symtabs == NULL)) {
		return 0;
	}

	for (i = 0; i < macho->symtab_count; i++) {
		symtab = macho->symtabs[i];
		if ((symtab == NULL) || (symtab->symbols == NULL)) {
			continue;
		}
		for (j = 0; j < symtab->nsyms; j++) {
			nl = &symtab->symbols[j];
			if (nl->n_un.n_name != NULL) {
				if (strcmp(sym, nl->n_un.n_name) == 0) {
					return nl->n_value;
				}
			}
		}
	}
	return 0;
}

void macho_list_symbols(macho_t* macho, void (*print_func)(const char*, uint64_t, void*), void* userdata) {
	int i = 0;
	int j = 0;
	macho_nlist_t* nl = NULL;
	macho_symtab_t* symtab = NULL;

	if ((macho == NULL) || (print_func == NULL) || (macho->symtabs == NULL)) {
		return;
	}

	for (i = 0; i < macho->symtab_count; i++) {
		symtab = macho->symtabs[i];
		if ((symtab == NULL) || (symtab->symbols == NULL)) {
			continue;
		}
		for (j = 0; j < symtab->nsyms; j++) {
			nl = &symtab->symbols[j];
			if ((nl->n_un.n_name != NULL) && (nl->n_value != 0)) {
				print_func(nl->n_un.n_name, nl->n_value, userdata);
			}
		}
	}
}

void macho_debug(macho_t* macho) {
	if (macho) {
		debug("Mach-O:\n");
		if (macho->is_fat && macho->fat && macho->fat->arches) {
			debug("\tFat binary with %u slice(s)\n", macho->fat->nfat_arch);
			uint32_t i;
			for (i = 0; i < macho->fat->nfat_arch; i++) {
				const macho_fat_arch_t* arch = &macho->fat->arches[i];
				const char* marker = (arch == macho->active_slice) ? "*" : " ";
				debug("\t\t%s cputype=0x%08x cpusubtype=0x%08x offset=0x%08x size=0x%08x align=%u\n",
						marker, arch->cputype, arch->cpusubtype, arch->offset, arch->size, arch->align);
			}
		}
		if (macho->header)
			macho_header_debug(macho->header);
		if (macho->commands)
			macho_commands_debug(macho->commands);
		if (macho->segments)
			macho_segments_debug(macho->segments);
		debug("\n");
	}
}

void macho_free(macho_t* macho) {
	if (macho) {
		macho_reset_parsed_state(macho);
		if (macho->fat) {
			macho_fat_free(macho->fat);
			macho->fat = NULL;
		}
		macho->raw_data = NULL;
		macho->raw_size = 0;
		macho->image_offset = 0;
		macho->is_fat = 0;
		macho->slice_count = 0;
		macho->active_slice = NULL;
		macho->data = NULL;
		macho->size = 0;
		macho->offset = 0;
		free(macho);
	}
}

int macho_select_architecture(macho_t* macho, uint32_t cputype, uint32_t cpusubtype) {
	if ((macho == NULL) || (macho->fat == NULL) || (macho->raw_data == NULL)) {
		return -1;
	}

	const macho_fat_arch_t* arch = macho_fat_find_arch(macho->fat, cputype, cpusubtype);
	if (arch == NULL) {
		return -1;
	}

	if ((arch->offset >= macho->raw_size) || (arch->size == 0) ||
		(arch->size > (macho->raw_size - arch->offset))) {
		return -1;
	}

	return macho_prepare_image(macho, macho->raw_data + arch->offset, arch->size, arch->offset, arch);
}

/*
 * Mach-O Header Functions
 */
macho_header_t* macho_header_create() {
	macho_header_t* header = (macho_header_t*) malloc(sizeof(macho_header_t));
	if (header) {
		memset(header, '\0', sizeof(macho_header_t));
	}
	return header;
}

macho_header_t* macho_header_load(macho_t* macho) {
	if (macho == NULL) {
		return NULL;
	}

	unsigned char* data = macho->data;
	unsigned int offset = macho->offset;
	macho_header_t* header = macho_header_create();
	if (header == NULL) {
		return NULL;
	}

	uint32_t magic = 0;
	memcpy(&magic, &data[offset], sizeof(uint32_t));
	if ((magic != MACHO_MAGIC_32) && (magic != MACHO_CIGAM_32) &&
		(magic != MACHO_MAGIC_64) && (magic != MACHO_CIGAM_64)) {
		macho_header_free(header);
		return NULL;
	}

	const macho_arch_ops_t* arch_ops = macho_arch_ops_for_magic(magic);
	if (arch_ops == NULL) {
		macho_header_free(header);
		return NULL;
	}

	arch_ops->header_reader(header, &data[offset]);
	macho->arch_ops = arch_ops;
	macho->offset += arch_ops->header_size;

	return header;
}

void macho_header_debug(macho_header_t* header) {
	if (header) {
		debug("\tHeader:\n");
		debug("\t\t     magic = 0x%08x\n", header->magic);
		debug("\t\t   cputype = 0x%08x\n", header->cputype);
		debug("\t\tcpusubtype = 0x%08x\n", header->cpusubtype);
		debug("\t\t  filetype = 0x%08x\n", header->filetype);
		debug("\t\t     ncmds = 0x%08x\n", header->ncmds);
		debug("\t\tsizeofcmds = 0x%08x\n", header->sizeofcmds);
		debug("\t\t     flags = 0x%08x\n", header->flags);
		if (header->is_64) {
			debug("\t\t  reserved = 0x%08x\n", header->reserved);
		}
		debug("\t\n");
	}
}

void macho_header_free(macho_header_t* header) {
	if (header) {
		free(header);
	}
}

int macho_handle_command(macho_t* macho, macho_command_t* command) {
	int ret = 0;
	if (macho) {
		//printf("handle command %x\n", command->info->cmd);
		// If load command is a segment command, then load a segment
		//  if a symbol table, then load a symbol table... etc...
		switch (command->info->cmd) {
		case MACHO_CMD_SEGMENT:
	case MACHO_CMD_SEGMENT_64:
		// segment of this file to be mapped
		{
		uint8_t is_segment_64 = (command->info->cmd == MACHO_CMD_SEGMENT_64);
		const macho_arch_ops_t* segment_arch = macho_arch_ops_for_flag(is_segment_64);
	if (macho->segments == NULL) {
		error("Segment storage not initialized\n");
		return -1;
	}
	macho_segment_t* seg = macho_segment_load(macho->data,
				command->offset, segment_arch);
			if (seg) {
				macho->segments[macho->segment_count++] = seg;
			} else {
				error(
						"Could not load segment at offset 0x%x\n", command->offset);
			}
		}
			break;
		case MACHO_CMD_SYMTAB:
			// link-edit stab symbol table info
		{
		const macho_arch_ops_t* arch = macho->arch_ops;
	if (macho->symtabs == NULL) {
		error("Symtab storage not initialized\n");
		return -1;
	}
	if (arch == NULL) {
		error("Architecture handlers not initialized\n");
		return -1;
	}
	macho_symtab_t* symtab = macho_symtab_load(arch, macho->data+command->offset, macho->data);
			if (symtab) {
				macho->symtabs[macho->symtab_count++] = symtab;
			} else {
				error(
						"Could not load symtab at offset 0x%x\n", command->offset);
			}
		}
			break;
		default:
			ret = -1;
			break;
		}
	}
	return ret;
}

/*
 * Mach-O Commands Functions
 */
macho_command_t** macho_commands_create(uint32_t count) {
	uint32_t size = (count + 1) * sizeof(macho_command_t*);
	macho_command_t** commands = (macho_command_t**) malloc(size);
	if (commands) {
		memset(commands, '\0', size);
	}
	return commands;
}

macho_command_t** macho_commands_load(macho_t* macho) {
	int i = 0;
	uint32_t count = 0;
	macho_command_t** commands = NULL;
	if (macho) {
		count = macho->command_count;
		//debug("Creating Mach-O commands array\n");
		commands = macho_commands_create(count);
		if (commands == NULL) {
			error("Unable to create Mach-O commands array\n");
			return NULL;
		}

		//debug("Loading Mach-O commands array\n");
		for (i = 0; i < count; i++) {
			//debug("Loading Mach-O command %d from offset 0x%x\n", i, macho->offset);
			commands[i] = macho_command_load(macho->data, macho->offset);
			if (commands[i] == NULL) {
				error("Unable to parse Mach-O load command\n");
				macho_commands_free(commands);
				return NULL;
			}
			macho->offset += commands[i]->size;
		}
	}
	return commands;
}

void macho_commands_debug(macho_command_t** commands) {
	int i = 0;
	if (commands) {
		debug("\tCommands:\n");
		while (commands[i] != NULL) {
			macho_command_debug(commands[i++]);
		}
		debug("\t\n");
	}
}

void macho_commands_free(macho_command_t** commands) {
	int i = 0;
	if (commands) {
		while (commands[i] != NULL) {
			macho_command_free(commands[i]);
			commands[i] = NULL;
			i++;
		}
		free(commands);
	}
}

/*
 * Mach-O Segments Functions
 */
macho_segment_t** macho_segments_create(uint32_t count) {
	if (count == 0)
		return NULL;
	int size = (count + 1) * sizeof(macho_segment_t*);
	macho_segment_t** segments = (macho_segment_t**) malloc(size);
	if (segments) {
		memset(segments, '\0', size);
	}
	return segments;
}

macho_segment_t** macho_segments_load(macho_t* macho) {
	macho_segment_t** segments = macho_segments_create(0);
	return segments;
}

void macho_segments_debug(macho_segment_t** segments) {
	debug("\tSegments:\n");
	if (segments) {
		int i = 0;
		while (segments[i]) {
			macho_segment_debug(segments[i]);
			i++;
		}
	}
	debug("\n");
}

void macho_segments_free(macho_segment_t** segments) {
	if (segments) {
		int i = 0;
		while (segments[i]) {
			macho_segment_free(segments[i]);
			segments[i] = NULL;
			i++;
		}
		free(segments);
	}
}

/*
 * Mach-O Symtab Functions
 */
macho_symtab_t** macho_symtabs_create(uint32_t count) {
	if (count == 0)
		return NULL;
	int size = (count + 1) * sizeof(macho_symtab_t*);
	macho_symtab_t** symtabs = (macho_symtab_t**) malloc(size);
	if (symtabs) {
		memset(symtabs, '\0', size);
	}
	return symtabs;
}

void macho_symtabs_debug(macho_symtab_t** symtabs) {
	debug("\tSymtabs:\n");
	if (symtabs) {
		int i = 0;
		while (symtabs[i]) {
			macho_symtab_debug(symtabs[i]);
			i++;
		}
	}
	debug("\n");
}

void macho_symtabs_free(macho_symtab_t** symtabs) {
	if (symtabs) {
		int i = 0;
		while (symtabs[i]) {
			macho_symtab_free(symtabs[i]);
			symtabs[i] = NULL;
			i++;
		}
		free(symtabs);
	}
}

/*
 * Mach-O Sections Functions
 */
macho_section_t** macho_sections_create(uint32_t count) {
	macho_section_t** sections = NULL;
	return sections;
}

macho_section_t** macho_sections_load(macho_t* macho) {
	macho_section_t** sections = macho_sections_create(0);
	return sections;
}

void macho_sections_debug(macho_section_t** sections) {
	debug("\tSections:\n");
	debug("\t\n");
}

void macho_sections_free(macho_section_t** sections) {
	// TODO: Loop through and free each item
	if (sections) {
		free(sections);
	}
}
