/**
 * GreenPois0n Absinthe - macho_segment.c
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
#include <string.h>
#include <inttypes.h>

#include <chronic/debug.h>
#include <chronic/chronic.h>
#include <macho/segment.h>

/*
 * Mach-O Segment Functions
 */
macho_segment_t* macho_segment_create() {
	macho_segment_t* segment = (macho_segment_t*) malloc(sizeof(macho_segment_t));
	if(segment) {
		memset(segment, '\0', sizeof(macho_segment_t));
	}
	return segment;
}

macho_segment_t* macho_segment_load(unsigned char* data, unsigned int offset, uint8_t is_64) {
	unsigned char* address = NULL;
	macho_segment_t* segment = macho_segment_create();
	if (segment) {
		segment->command = macho_segment_cmd_load(data, offset, is_64);
		if (!segment->command) {
			macho_segment_free(segment);
			return NULL;
		}
		segment->is_64 = is_64;
		segment->name = malloc(sizeof(segment->command->segname) + 1);
		if (segment->name) {
			memcpy(segment->name, segment->command->segname, sizeof(segment->command->segname));
			segment->name[sizeof(segment->command->segname)] = '\0';
		}
		segment->size = segment->command->filesize;
		segment->offset = segment->command->fileoff;
		segment->address = segment->command->vmaddr;
		if (segment->command->filesize > 0 && data) {
			segment->data = data + segment->offset;
		} else {
			segment->data = NULL;
		}
		//segment->sections = malloc(segment->cmd->nsects * sizeof(macho_section_t*));
	}
	return segment;
}

void macho_segment_debug(macho_segment_t* segment) {
	debug("\tSegment:\n");
	debug("\t\tname: %s\n", segment->name);
	debug("\t\tsize: 0x%016" PRIx64 "\n", segment->size);
	debug("\t\toffset: 0x%016" PRIx64 "\n", segment->offset);
	debug("\t\taddress: 0x%016" PRIx64 "\n", segment->address);
}

void macho_segment_free(macho_segment_t* segment) {
	if (segment) {
		if (segment->command) {
			macho_segment_cmd_free(segment->command);
		}
		if (segment->name) {
			free(segment->name);
		}
		free(segment);
	}
}

/*
 * Mach-O Segment Info Functions
 */
macho_segment_cmd_t* macho_segment_cmd_create() {
	macho_segment_cmd_t* info = malloc(sizeof(macho_segment_cmd_t));
	if (info) {
		memset(info, '\0', sizeof(macho_segment_cmd_t));
	}
	return info;
}

macho_segment_cmd_t* macho_segment_cmd_load(unsigned char* data, unsigned int offset, uint8_t is_64) {
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

	macho_segment_cmd_t* cmd = macho_segment_cmd_create();
	if (cmd == NULL) {
		return NULL;
	}

	if (is_64) {
		macho_segment_cmd64_disk_t disk = { 0 };
		memcpy(&disk, data+offset, sizeof(macho_segment_cmd64_disk_t));
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
	} else {
		macho_segment_cmd32_disk_t disk = { 0 };
		memcpy(&disk, data+offset, sizeof(macho_segment_cmd32_disk_t));
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
	//macho_segment_cmd_debug(cmd);
	return cmd;
}

void macho_segment_cmd_debug(macho_segment_cmd_t* cmd) {
	debug("\tSegment Command:\n");
	debug("\t\t     cmd = 0x%x\n", cmd->cmd);
	debug("\t\t cmdsize = 0x%x\n", cmd->cmdsize);
	debug("\t\t segname = %s\n", cmd->segname);
	debug("\t\t  vmaddr = 0x%016" PRIx64 "\n", cmd->vmaddr);
	debug("\t\t  vmsize = 0x%016" PRIx64 "\n", cmd->vmsize);
	debug("\t\t fileoff = 0x%016" PRIx64 "\n", cmd->fileoff);
	debug("\t\tfilesize = 0x%016" PRIx64 "\n", cmd->filesize);
	debug("\t\t maxprot = 0x%08x\n", cmd->maxprot);
	debug("\t\tinitprot = 0x%08x\n", cmd->initprot);
	debug("\t\t  nsects = 0x%x\n", cmd->nsects);
	debug("\t\t   flags = 0x%08x\n", cmd->flags);
}

void macho_segment_cmd_free(macho_segment_cmd_t* cmd) {
	if (cmd) {
		free(cmd);
	}
}
