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
	typedef struct {
		int32_t  n_strx;
		uint8_t  n_type;
		uint8_t  n_sect;
		int16_t  n_desc;
		uint32_t n_value;
	} nlist_disk32_t;

	typedef struct {
		uint32_t n_strx;
		uint8_t  n_type;
		uint8_t  n_sect;
		uint16_t n_desc;
		uint64_t n_value;
	} nlist_disk64_t;

	macho_symtab_t* symtab = macho_symtab_create();
	if (symtab) {
		symtab->cmd = macho_symtab_cmd_load(cmd);
		if (!symtab->cmd) {
			macho_symtab_free(symtab);
			return NULL;
		}
		symtab->nsyms = symtab->cmd->nsyms;
		symtab->is_64 = is_64;
		symtab->symbols = malloc(symtab->nsyms * sizeof(macho_nlist_t));
		if (!symtab->symbols) {
			macho_symtab_free(symtab);
			return NULL;
		}
		memset(symtab->symbols, 0, symtab->nsyms * sizeof(macho_nlist_t));
		int i;
		if (is_64) {
			nlist_disk64_t* syms = (nlist_disk64_t*)(data + symtab->cmd->symoff);
			for (i = 0; i < symtab->nsyms; i++) {
				uint32_t strx = syms[i].n_strx;
				symtab->symbols[i].n_type  = syms[i].n_type;
				symtab->symbols[i].n_sect  = syms[i].n_sect;
				symtab->symbols[i].n_desc  = (int16_t)syms[i].n_desc;
				symtab->symbols[i].n_value = syms[i].n_value;
				if (strx >= symtab->cmd->strsize) {
					symtab->symbols[i].n_un.n_name = NULL;
				} else {
					symtab->symbols[i].n_un.n_name = (char*)(data + symtab->cmd->stroff + strx);
				}
			}
		} else {
			nlist_disk32_t* syms = (nlist_disk32_t*)(data + symtab->cmd->symoff);
			for (i = 0; i < symtab->nsyms; i++) {
				uint32_t strx = (uint32_t)syms[i].n_strx;
				symtab->symbols[i].n_type  = syms[i].n_type;
				symtab->symbols[i].n_sect  = syms[i].n_sect;
				symtab->symbols[i].n_desc  = syms[i].n_desc;
				symtab->symbols[i].n_value = syms[i].n_value;
				if (strx >= symtab->cmd->strsize) {
					symtab->symbols[i].n_un.n_name = NULL;
				} else {
					symtab->symbols[i].n_un.n_name = (char*)(data + symtab->cmd->stroff + strx);
				}
			}
		}
		//macho_symtab_debug(symtab);
	}
	return symtab;
}

void macho_symtab_debug(macho_symtab_t* symtab) {
	debug("\tSymtab:\n");
	debug("\t\tnsyms: 0x%08x\n", symtab->nsyms);
	int i;
	for (i = 0; i < symtab->nsyms; i++) {
		macho_nlist_t* sym = &symtab->symbols[i];
		if (sym->n_un.n_name) {
			debug("\t\t0x%x\tname=%s\n", i, sym->n_un.n_name);
		} else {
			debug("\t\t0x%x\tname=(no name)\n", i);
		}
		debug("\t\t\tn_type=0x%02x,n_sect=0x%02x,n_desc=0x%04x,n_value=0x%016" PRIx64 "\n", sym->n_type, sym->n_sect, sym->n_desc, sym->n_value);
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
