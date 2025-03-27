#include "elf.h"
#include "fs.h"
#include "../mm/memory.h"
#include <string.h>
#include <stddef.h>
#include <stdio.h>

// Forward declarations
static char* find_library(const char* name);
static int handle_got_relocation(struct library* lib, struct elf32_rel* rel,
                               struct elf32_symbol* sym, const char* sym_name) __attribute__((unused));
static int handle_plt_relocation(struct library* lib, struct elf32_rel* rel,
                               struct elf32_symbol* sym, const char* sym_name) __attribute__((unused));
static int init_got(struct library* lib) __attribute__((unused));
static int init_plt(struct library* lib) __attribute__((unused));

// Library search paths
#define MAX_SEARCH_PATHS 16
static char* library_search_paths[MAX_SEARCH_PATHS];
static int num_search_paths = 0;

// Loaded libraries
#define MAX_LOADED_LIBS 32
struct loaded_library {
    char name[MAX_FILENAME];
    void* base_addr;
    struct elf32_header* header;
    struct loaded_library* next;
};
static struct loaded_library* loaded_libraries = 0;

// Dynamic linker instance
static struct dynamic_linker linker;

// GOT entry types
#define GOT_ENTRY_SIZE 4
#define GOT_ENTRY_COUNT 1024

// PLT entry structure
struct plt_entry {
    uint8_t push;    // pushl $offset
    uint8_t jmp;     // jmp *offset
    uint32_t offset; // offset into GOT
};

// Initialize dynamic linking
int dynamic_init(void) {
    memset(&linker, 0, sizeof(struct dynamic_linker));
    linker.malloc = kmalloc;
    linker.free = kfree;
    return 0;
}

// Find library in search paths
const char* dynamic_find_library(const char* name) {
    char path[MAX_FILENAME];
    
    // Try each search path
    for (int i = 0; i < linker.num_search_paths; i++) {
        snprintf(path, sizeof(path), "%s/%s", linker.search_paths[i], name);
        if (fs_file_exists(path)) {
            return strdup(path);
        }
    }
    
    return 0;
}

// Add library search path
int dynamic_add_search_path(const char* path) {
    if (!path || linker.num_search_paths >= MAX_LIBRARY_PATHS) {
        return -1;
    }
    
    linker.search_paths[linker.num_search_paths++] = strdup(path);
    return 0;
}

// Set memory allocator functions
void dynamic_set_allocator(void* (*malloc)(size_t size), void (*free)(void* ptr)) {
    linker.malloc = malloc;
    linker.free = free;
}

// Initialize GOT for a library
static int init_got(struct library* lib) {
    if (!lib || !lib->dynamic) return -1;
    
    // Find GOT section
    struct elf32_section_header* got_section = 0;
    for (int i = 0; i < lib->header->e_shnum; i++) {
        struct elf32_section_header* sh = (struct elf32_section_header*)
            ((char*)lib->base + lib->header->e_shoff + i * lib->header->e_shentsize);
        if (sh->sh_type == SHT_PROGBITS && (sh->sh_flags & SHF_ALLOC)) {
            // Check if this is the GOT section
            const char* section_name = (const char*)
                ((char*)lib->base + lib->header->e_shstrndx + sh->sh_name);
            if (strcmp(section_name, ".got") == 0) {
                got_section = sh;
                break;
            }
        }
    }
    
    if (!got_section) return -1;
    
    // Allocate GOT in memory
    void* got = linker.malloc(got_section->sh_size);
    if (!got) return -1;
    
    // Copy GOT data
    memcpy(got, (char*)lib->base + got_section->sh_offset, got_section->sh_size);
    
    // Store GOT pointer in library structure
    lib->got = got;
    
    return 0;
}

// Initialize PLT for a library
static int init_plt(struct library* lib) {
    if (!lib || !lib->dynamic) return -1;
    
    // Find PLT section
    struct elf32_section_header* plt_section = 0;
    for (int i = 0; i < lib->header->e_shnum; i++) {
        struct elf32_section_header* sh = (struct elf32_section_header*)
            ((char*)lib->base + lib->header->e_shoff + i * lib->header->e_shentsize);
        if (sh->sh_type == SHT_PROGBITS && (sh->sh_flags & SHF_ALLOC)) {
            // Check if this is the PLT section
            const char* section_name = (const char*)
                ((char*)lib->base + lib->header->e_shstrndx + sh->sh_name);
            if (strcmp(section_name, ".plt") == 0) {
                plt_section = sh;
                break;
            }
        }
    }
    
    if (!plt_section) return -1;
    
    // Allocate PLT in memory
    void* plt = linker.malloc(plt_section->sh_size);
    if (!plt) return -1;
    
    // Copy PLT data
    memcpy(plt, (char*)lib->base + plt_section->sh_offset, plt_section->sh_size);
    
    // Store PLT pointer in library structure
    lib->plt = plt;
    
    return 0;
}

// Load library
int dynamic_load_library(const char* name, struct library** lib) {
    if (!name || !lib) return -1;
    
    // Check if library is already loaded
    struct library* existing = linker.libraries;
    while (existing) {
        if (strcmp(existing->name, name) == 0) {
            existing->refcount++;
            *lib = existing;
            return 0;
        }
        existing = existing->next;
    }
    
    // Find library file
    const char* path = dynamic_find_library(name);
    if (!path) return -1;
    
    // Load library file
    struct file* file = fs_open(path, FF_OPEN);
    if (!file) return -1;
    
    // Allocate library structure
    struct library* new_lib = linker.malloc(sizeof(struct library));
    if (!new_lib) {
        fs_close(file);
        return -1;
    }
    
    memset(new_lib, 0, sizeof(struct library));
    strncpy(new_lib->name, name, MAX_LIBRARY_NAME - 1);
    new_lib->refcount = 1;
    
    // Read file into memory
    new_lib->base = linker.malloc(file->size);
    if (!new_lib->base) {
        linker.free(new_lib);
        fs_close(file);
        return -1;
    }
    
    if (fs_read(file, new_lib->base, file->size, 0) < 0) {
        linker.free(new_lib->base);
        linker.free(new_lib);
        fs_close(file);
        return -1;
    }
    
    // Parse ELF header
    new_lib->header = (struct elf32_header*)new_lib->base;
    if (elf_validate_header(new_lib->header) < 0) {
        linker.free(new_lib->base);
        linker.free(new_lib);
        fs_close(file);
        return -1;
    }
    
    // Add to library list
    new_lib->next = linker.libraries;
    linker.libraries = new_lib;
    
    // Load required libraries
    if (dynamic_load_required_libs(new_lib->header) < 0) {
        dynamic_unload_library(new_lib);
        fs_close(file);
        return -1;
    }
    
    // Perform relocations
    if (dynamic_relocate(new_lib) < 0) {
        dynamic_unload_library(new_lib);
        fs_close(file);
        return -1;
    }
    
    *lib = new_lib;
    fs_close(file);
    return 0;
}

// Resolve symbol
int dynamic_resolve_symbol(const char* name, void** addr) {
    if (!name || !addr) return -1;
    
    // Search in all loaded libraries
    struct library* lib = linker.libraries;
    while (lib) {
        // Find symbol table
        struct elf32_section_header* symtab = 0;
        struct elf32_section_header* strtab = 0;
        
        for (int i = 0; i < lib->header->e_shnum; i++) {
            struct elf32_section_header* sh = (struct elf32_section_header*)
                ((char*)lib->base + lib->header->e_shoff + i * lib->header->e_shentsize);
            if (sh->sh_type == SHT_SYMTAB) {
                symtab = sh;
            } else if (sh->sh_type == SHT_STRTAB) {
                strtab = sh;
            }
        }
        
        if (!symtab || !strtab) {
            lib = lib->next;
            continue;
        }
        
        // Search symbol table
        struct elf32_symbol* sym = (struct elf32_symbol*)
            ((char*)lib->base + symtab->sh_offset);
        int num_syms = symtab->sh_size / symtab->sh_entsize;
        
        for (int i = 0; i < num_syms; i++) {
            const char* sym_name = (const char*)
                ((char*)lib->base + strtab->sh_offset + sym[i].st_name);
            if (strcmp(sym_name, name) == 0) {
                *addr = (void*)((char*)lib->base + sym[i].st_value);
                return 0;
            }
        }
        
        lib = lib->next;
    }
    
    return -1;
}

// Handle GOT relocation
static int handle_got_relocation(struct library* lib, struct elf32_rel* rel,
                               struct elf32_symbol* sym, const char* sym_name) {
    if (!lib || !lib->got) return -1;
    
    // Get GOT entry
    uint32_t got_index = rel->r_offset / GOT_ENTRY_SIZE;
    uint32_t* got_entry = (uint32_t*)((char*)lib->got + got_index * GOT_ENTRY_SIZE);
    
    // Resolve symbol
    void* sym_addr;
    if (dynamic_resolve_symbol(sym_name, &sym_addr) < 0) {
        return -1;
    }
    
    // Update GOT entry
    *got_entry = (uint32_t)sym_addr;
    
    return 0;
}

// Handle PLT relocation
static int handle_plt_relocation(struct library* lib, struct elf32_rel* rel,
                               struct elf32_symbol* sym, const char* sym_name) {
    if (!lib || !lib->plt) return -1;
    
    // Get PLT entry
    uint32_t plt_index = (rel->r_offset - lib->plt_offset) / sizeof(struct plt_entry);
    struct plt_entry* plt_entry = (struct plt_entry*)
        ((char*)lib->plt + plt_index * sizeof(struct plt_entry));
    
    // Resolve symbol
    void* sym_addr;
    if (dynamic_resolve_symbol(sym_name, &sym_addr) < 0) {
        return -1;
    }
    
    // Update PLT entry
    plt_entry->push = 0x68;  // pushl
    plt_entry->jmp = 0xFF;   // jmp
    plt_entry->offset = (uint32_t)sym_addr;
    
    return 0;
}

// Relocate library
int dynamic_relocate(struct library* lib) {
    if (!lib || !lib->dynamic) return -1;
    
    // Find relocation sections
    struct elf32_section_header* rel = 0;
    struct elf32_section_header* plt_rel = 0;
    struct elf32_section_header* symtab = 0;
    struct elf32_section_header* strtab = 0;
    
    for (int i = 0; i < lib->header->e_shnum; i++) {
        struct elf32_section_header* sh = (struct elf32_section_header*)
            ((char*)lib->base + lib->header->e_shoff + i * lib->header->e_shentsize);
        if (sh->sh_type == SHT_REL) {
            rel = sh;
        } else if (sh->sh_type == SHT_RELA) {
            rel = sh;
        } else if (sh->sh_type == SHT_SYMTAB) {
            symtab = sh;
        } else if (sh->sh_type == SHT_STRTAB) {
            strtab = sh;
        }
    }
    
    if (!rel || !symtab || !strtab) return -1;
    
    // Process relocations
    struct elf32_rel* rel_entries = (struct elf32_rel*)
        ((char*)lib->base + rel->sh_offset);
    int num_rels = rel->sh_size / rel->sh_entsize;
    
    for (int i = 0; i < num_rels; i++) {
        uint32_t type = ELF32_R_TYPE(rel_entries[i].r_info);
        uint32_t sym_idx = ELF32_R_SYM(rel_entries[i].r_info);
        
        // Get symbol
        struct elf32_symbol* sym = (struct elf32_symbol*)
            ((char*)lib->base + symtab->sh_offset + sym_idx * symtab->sh_entsize);
        const char* sym_name = (const char*)
            ((char*)lib->base + strtab->sh_offset + sym->st_name);
        
        // Handle relocation
        switch (type) {
            case R_386_32: {
                void* sym_addr;
                if (dynamic_resolve_symbol(sym_name, &sym_addr) < 0) {
                    return -1;
                }
                uint32_t* target = (uint32_t*)((char*)lib->base + rel_entries[i].r_offset);
                *target += (uint32_t)sym_addr;
                break;
            }
            case R_386_PC32: {
                void* sym_addr;
                if (dynamic_resolve_symbol(sym_name, &sym_addr) < 0) {
                    return -1;
                }
                uint32_t* target = (uint32_t*)((char*)lib->base + rel_entries[i].r_offset);
                *target += (uint32_t)sym_addr - (uint32_t)target - 4;
                break;
            }
            case R_386_GOT32: {
                if (handle_got_relocation(lib, &rel_entries[i], sym, sym_name) < 0) {
                    return -1;
                }
                break;
            }
            case R_386_PLT32: {
                if (handle_plt_relocation(lib, &rel_entries[i], sym, sym_name) < 0) {
                    return -1;
                }
                break;
            }
        }
    }
    
    return 0;
}

// Unload library
void dynamic_unload_library(struct library* lib) {
    if (!lib) return;
    
    // Decrement reference count
    lib->refcount--;
    if (lib->refcount > 0) return;
    
    // Remove from library list
    if (linker.libraries == lib) {
        linker.libraries = lib->next;
    } else {
        struct library* prev = linker.libraries;
        while (prev && prev->next != lib) {
            prev = prev->next;
        }
        if (prev) {
            prev->next = lib->next;
        }
    }
    
    // Free GOT and PLT
    if (lib->got) linker.free(lib->got);
    if (lib->plt) linker.free(lib->plt);
    
    // Free library data
    linker.free(lib->base);
    linker.free(lib);
}

// Load required libraries for an executable
int dynamic_load_required_libs(const struct elf32_header* header) {
    if (!header) return -1;
    
    // Get dynamic section
    struct elf32_section_header* sections = 
        (struct elf32_section_header*)((char*)header + header->e_shoff);
    
    struct elf32_section_header* dynamic_section = 0;
    for (uint16_t i = 0; i < header->e_shnum; i++) {
        if (sections[i].sh_type == SHT_DYNAMIC) {
            dynamic_section = &sections[i];
            break;
        }
    }
    
    if (!dynamic_section) return 0;  // No dynamic section
    
    // Process dynamic entries
    struct elf32_dynamic* dynamic = 
        (struct elf32_dynamic*)((char*)header + dynamic_section->sh_offset);
    
    while (dynamic->d_tag != DT_NULL) {
        if (dynamic->d_tag == DT_NEEDED) {
            // Get library name from string table
            const char* strtab = (const char*)((char*)header + 
                sections[header->e_shstrndx].sh_offset);
            const char* lib_name = strtab + dynamic->d_un.d_val;
            
            // Load library
            struct library* lib;
            if (dynamic_load_library(lib_name, &lib) < 0) {
                return -1;
            }
        }
        dynamic++;
    }
    
    return 0;
}

// Load a library
static struct loaded_library* load_library(const char* name) {
    // Check if already loaded
    struct loaded_library* lib = loaded_libraries;
    while (lib) {
        if (strcmp(lib->name, name) == 0) {
            return lib;
        }
        lib = lib->next;
    }
    
    // Find library file
    char* path = find_library(name);
    if (!path) return 0;
    
    // Open and read library
    struct file* file = fs_open(path, FF_OPEN);
    if (!file) {
        kfree(path);
        return 0;
    }
    
    struct inode* inode = fs_get_inode(file->inode);
    if (!inode) {
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Allocate memory for library
    void* file_data = kmalloc(inode->size);
    if (!file_data) {
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Read library data
    if (fs_read(file, file_data, inode->size, 0) < 0) {
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Parse ELF header
    struct elf32_header* header = (struct elf32_header*)file_data;
    if (elf_validate_header(header) < 0) {
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Allocate library structure
    struct loaded_library* new_lib = kmalloc(sizeof(struct loaded_library));
    if (!new_lib) {
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Initialize library structure
    strncpy(new_lib->name, name, MAX_FILENAME - 1);
    new_lib->name[MAX_FILENAME - 1] = '\0';
    new_lib->header = header;
    new_lib->base_addr = 0;  // Will be set after loading
    new_lib->next = 0;
    
    // Load library sections
    if (elf_load_sections(header, file_data) < 0) {
        kfree(new_lib);
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Load program headers
    if (elf_load_program_headers(header, file_data) < 0) {
        kfree(new_lib);
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Set up memory protection
    if (elf_setup_memory_protection(header) < 0) {
        kfree(new_lib);
        kfree(file_data);
        fs_close(file);
        kfree(path);
        return 0;
    }
    
    // Add to loaded libraries list
    if (!loaded_libraries) {
        loaded_libraries = new_lib;
    } else {
        lib = loaded_libraries;
        while (lib->next) lib = lib->next;
        lib->next = new_lib;
    }
    
    // Clean up
    kfree(file_data);
    fs_close(file);
    kfree(path);
    
    return new_lib;
}

// Find library file
static char* find_library(const char* name) {
    char path[MAX_FILENAME];
    
    // Try search paths
    for (int i = 0; i < num_search_paths; i++) {
        snprintf(path, MAX_FILENAME, "%s/%s", library_search_paths[i], name);
        if (fs_path_to_inode(path, 0) == 0) {
            char* result = kmalloc(strlen(path) + 1);
            if (result) {
                strcpy(result, path);
                return result;
            }
        }
    }
    
    // Try current directory
    if (fs_path_to_inode(name, 0) == 0) {
        char* result = kmalloc(strlen(name) + 1);
        if (result) {
            strcpy(result, name);
            return result;
        }
    }
    
    return 0;
} 