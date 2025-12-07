/**
 * GreenPois0n Absinthe - macho_symtab.c
 * Copyright (C) 2011 Chronic-Dev Team
 * Copyright (C) 2011 Hanéne Samara
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
#include <macho/symtab.h>

/*
 * Mach-O Symtab Functions
 */
macho_symtab_t* macho_symtab_create() {
	macho_symtab_t* symtab = malloc(sizeof(macho_symtab_t));
	if (symtab) {
		memset(symtab, '\0', sizeof(macho_symtab_t));
	}
	return symtab;
}

macho_symtab_t* macho_symtab_load(unsigned char* cmd, unsigned char* data, uint8_t is_64) {
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

	if ((cmd == NULL) || (data == NULL)) {
		return NULL;
	}

	macho_symtab_t* symtab = macho_symtab_create();
	if (symtab == NULL) {
		return NULL;
	}

	symtab->cmd = macho_symtab_cmd_load(cmd);
	if (!symtab->cmd) {
		macho_symtab_free(symtab);
		return NULL;
	}

	symtab->is_64 = is_64 ? 1 : 0;
	symtab->nsyms = symtab->cmd->nsyms;
	if (symtab->nsyms == 0) {
		symtab->symbols = NULL;
		return symtab;
	}

	size_t alloc_size = (size_t) symtab->nsyms * sizeof(macho_nlist_t);
	symtab->symbols = (macho_nlist_t*) malloc(alloc_size);
	if (symtab->symbols == NULL) {
		macho_symtab_free(symtab);
		return NULL;
	}
	memset(symtab->symbols, '\0', alloc_size);

	unsigned char* sym_base = data + symtab->cmd->symoff;
	unsigned char* str_base = data + symtab->cmd->stroff;
	size_t entry_size = symtab->is_64 ? sizeof(macho_nlist64_disk_t) : sizeof(macho_nlist32_disk_t);

	uint32_t i;
	for (i = 0; i < symtab->nsyms; i++) {
		macho_nlist_t* dest = &symtab->symbols[i];
		if (symtab->is_64) {
			macho_nlist64_disk_t disk = { 0 };
			memcpy(&disk, sym_base + (i * entry_size), sizeof(macho_nlist64_disk_t));
			dest->n_un.n_strx = disk.n_un.n_strx;
			dest->n_type = disk.n_type;
			dest->n_sect = disk.n_sect;
			dest->n_desc = disk.n_desc;
			dest->n_value = disk.n_value;
		} else {
			macho_nlist32_disk_t disk = { 0 };
			memcpy(&disk, sym_base + (i * entry_size), sizeof(macho_nlist32_disk_t));
			dest->n_un.n_strx = disk.n_un.n_strx;
			dest->n_type = disk.n_type;
			dest->n_sect = disk.n_sect;
			dest->n_desc = disk.n_desc;
			dest->n_value = disk.n_value;
		}

		if ((dest->n_un.n_strx < 0)
				|| ((uint32_t) dest->n_un.n_strx >= symtab->cmd->strsize)) {
			dest->n_un.n_name = NULL;
		} else {
			dest->n_un.n_name = (char*) (str_base + dest->n_un.n_strx);
		}
	}

	return symtab;
}

void macho_symtab_debug(macho_symtab_t* symtab) {
	if (symtab == NULL) {
		return;
	}
	debug("\tSymtab:\n");
	debug("\t\tnsyms: 0x%08x (is64=%d)\n", symtab->nsyms, symtab->is_64);
	if (symtab->symbols == NULL) {
		return;
	}
	uint32_t i;
	for (i = 0; i < symtab->nsyms; i++) {
		macho_nlist_t sym = symtab->symbols[i];
		if (sym.n_un.n_name) {
			debug("\t\t0x%x\tname=%s\n", i, sym.n_un.n_name);
		} else {
			debug("\t\t0x%x\tname=(no name)\n", i);
		}
		debug("\t\t\tn_type=0x%02x,n_sect=0x%02x,n_desc=0x%04x,n_value=0x%016" PRIx64 "\n",
				sym.n_type, sym.n_sect, sym.n_desc, sym.n_value);
	}
}

void macho_symtab_free(macho_symtab_t* symtab) {
	if (symtab) {
		if (symtab->cmd) {
			macho_symtab_cmd_free(symtab->cmd);
		}
		if (symtab->symbols) {
			free(symtab->symbols);
		}
		free(symtab);
	}
}

/*
 * Mach-O Symtab Info Functions
 */
macho_symtab_cmd_t* macho_symtab_cmd_create() {
	macho_symtab_cmd_t* info = malloc(sizeof(macho_symtab_cmd_t));
	if (info) {
		memset(info, '\0', sizeof(macho_symtab_cmd_t));
	}
	return info;
}

macho_symtab_cmd_t* macho_symtab_cmd_load(unsigned char* data) {
	if (data == NULL) {
		return NULL;
	}
	macho_symtab_cmd_t* cmd = macho_symtab_cmd_create();
	if (cmd) {
		memcpy(cmd, data, sizeof(macho_symtab_cmd_t));
		//macho_symtab_cmd_debug(cmd);
	}
	return cmd;
}

void macho_symtab_cmd_debug(macho_symtab_cmd_t* cmd) {
	debug("\tSymtab Command:\n");
	debug("\t\t     cmd = 0x%x\n", cmd->cmd);
	debug("\t\t cmdsize = 0x%x\n", cmd->cmdsize);
	debug("\t\t  symoff = 0x%x\n", cmd->symoff);
	debug("\t\t   nsyms = 0x%x\n", cmd->nsyms);
	debug("\t\t  stroff = 0x%x\n", cmd->stroff);
	debug("\t\t strsize = 0x%x\n", cmd->strsize);
}

void macho_symtab_cmd_free(macho_symtab_cmd_t* cmd) {
	if (cmd) {
		free(cmd);
	}
}
