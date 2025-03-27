#ifndef _KERNEL_FS_DYNAMIC_H
#define _KERNEL_FS_DYNAMIC_H

#include <stdint.h>
#include "elf.h"

// Dynamic entry types
#define DT_NULL          0
#define DT_NEEDED        1
#define DT_PLTRELSZ      2
#define DT_PLTGOT        3
#define DT_HASH          4
#define DT_STRTAB        5
#define DT_SYMTAB        6
#define DT_RELA          7
#define DT_RELASZ        8
#define DT_RELAENT       9
#define DT_STRSZ         10
#define DT_SYMENT        11
#define DT_INIT          12
#define DT_FINI          13
#define DT_SONAME        14
#define DT_RPATH         15
#define DT_SYMBOLIC      16
#define DT_REL           17
#define DT_RELSZ         18
#define DT_RELENT        19
#define DT_PLTREL        20
#define DT_DEBUG         21
#define DT_TEXTREL       22
#define DT_JMPREL        23
#define DT_BIND_NOW      24
#define DT_INIT_ARRAY    25
#define DT_FINI_ARRAY    26
#define DT_INIT_ARRAYSZ  27
#define DT_FINI_ARRAYSZ  28
#define DT_RUNPATH       29
#define DT_FLAGS         30
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33
#define DT_NUM              34

// Dynamic linking flags
#define DF_ORIGIN        0x00000001
#define DF_SYMBOLIC      0x00000002
#define DF_TEXTREL       0x00000004
#define DF_BIND_NOW      0x00000008
#define DF_STATIC_TLS    0x00000010

// Library search paths
#define MAX_LIBRARY_PATHS 16
#define MAX_LIBRARY_NAME  256

// GOT entry types
#define GOT_ENTRY_SIZE 4
#define GOT_ENTRY_COUNT 1024

// PLT entry structure
struct plt_entry {
    uint8_t push;    // pushl $offset
    uint8_t jmp;     // jmp *offset
    uint32_t offset; // offset into GOT
};

// Library structure
struct library {
    char name[MAX_LIBRARY_NAME];
    void* base;
    struct elf32_header* header;
    struct elf32_dynamic* dynamic;
    struct library* next;
    int refcount;
    void* got;
    void* plt;
    uint32_t plt_offset;
    void (*init)(void);
    void (*fini)(void);
    void (**init_array)(void);
    void (**fini_array)(void);
    size_t init_array_size;
    size_t fini_array_size;
};

// Dynamic linking structure
struct dynamic_linker {
    struct library* libraries;
    char* search_paths[MAX_LIBRARY_PATHS];
    int num_search_paths;
    void* (*malloc)(size_t size);
    void (*free)(void* ptr);
};

// Function declarations
int dynamic_init(void);
int dynamic_load_library(const char* name, struct library** lib);
int dynamic_resolve_symbol(const char* name, void** addr);
int dynamic_relocate(struct library* lib);
void dynamic_unload_library(struct library* lib);
int dynamic_add_search_path(const char* path);
const char* dynamic_find_library(const char* name);
void dynamic_set_allocator(void* (*malloc)(size_t size), void (*free)(void* ptr));
int dynamic_load_required_libs(const struct elf32_header* header);

#endif // _KERNEL_FS_DYNAMIC_H 