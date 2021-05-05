#ifndef VITA_ELF_H
#define VITA_ELF_H

#include <elf.h>
#include <stdbool.h>
#include <stdint.h>

/* These fields must always come at the beginning of the NID-bearing structs */
typedef struct
{
    char *name;
    uint32_t NID;
} vita_imports_common_fields;

typedef struct
{
    char *name;
    uint32_t NID;
} vita_imports_stub_t;

typedef struct
{
    char *name;
    uint32_t NID;
    bool is_kernel;
    vita_imports_stub_t **functions;
    vita_imports_stub_t **variables;
    int n_functions;
    int n_variables;
    uint32_t flags;
} vita_imports_lib_t;

typedef struct
{
    char *name;
    uint32_t NID;
    vita_imports_lib_t **libs;
    int n_libs;
} vita_imports_module_t;

typedef struct
{
    char *firmware;
    char *postfix;
    vita_imports_module_t **modules;
    int n_modules;
} vita_imports_t;

/* Convenience representation of a symtab entry */
typedef struct vita_elf_symbol_t
{
    const char *name;
    Elf32_Addr value;
    uint8_t type;
    uint8_t binding;
    int shndx;
} vita_elf_symbol_t;

typedef struct vita_elf_rela_t
{
    uint8_t type;
    vita_elf_symbol_t *symbol;
    Elf32_Addr offset;
    Elf32_Sword addend;
} vita_elf_rela_t;

typedef struct vita_elf_rela_table_t
{
    vita_elf_rela_t *relas;
    int num_relas;

    int target_ndx;

    struct vita_elf_rela_table_t *next;
} vita_elf_rela_table_t;

typedef struct vita_elf_stub_t
{
    Elf32_Addr addr;
    uint32_t library_nid;
    uint32_t target_nid;

    vita_elf_symbol_t *symbol;

    vita_imports_lib_t *library;
    vita_imports_stub_t *target;
} vita_elf_stub_t;

typedef struct vita_elf_segment_info_t
{
    Elf32_Word type;  /* Segment type */
    Elf32_Addr vaddr; /* Top of segment space on TARGET */
    Elf32_Word memsz; /* Size of segment space */

    /* vaddr_top/vaddr_bottom point to a reserved, unallocated memory space that
	 * represents the segment space in the HOST.  This space can be used as
	 * pointer targets for translated data structures. */
    const void *vaddr_top;
    const void *vaddr_bottom;
} vita_elf_segment_info_t;

#endif