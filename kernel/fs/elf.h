#ifndef _ELF_H
#define _ELF_H

#include <stdint.h>

// ELF file class
#define ELFCLASS32    1
#define ELFCLASS64    2

// ELF data encoding
#define ELFDATA2LSB   1
#define ELFDATA2MSB   2

// ELF file type
#define ET_NONE       0
#define ET_REL        1
#define ET_EXEC       2
#define ET_DYN        3
#define ET_CORE       4
#define ET_LOPROC     0xFF00
#define ET_HIPROC     0xFFFF

// ELF machine types
#define EM_386         3
#define EM_486         6
#define EM_X86_64      62

// ELF version
#define EV_NONE        0
#define EV_CURRENT     1

// Section types
#define SHT_NULL       0
#define SHT_PROGBITS   1
#define SHT_SYMTAB     2
#define SHT_STRTAB     3
#define SHT_RELA       4
#define SHT_HASH       5
#define SHT_DYNAMIC    6
#define SHT_NOTE       7
#define SHT_NOBITS     8
#define SHT_REL        9
#define SHT_SHLIB      10
#define SHT_DYNSYM     11
#define SHT_INIT_ARRAY 14
#define SHT_FINI_ARRAY 15
#define SHT_PREINIT_ARRAY 16
#define SHT_GROUP      17
#define SHT_SYMTAB_SHNDX 18
#define SHT_NUM        19
#define SHT_LOOS       0x60000000
#define SHT_HIOS       0x6FFFFFFF
#define SHT_LOPROC     0x70000000
#define SHT_HIPROC     0x7FFFFFFF
#define SHT_LOUSER     0x80000000
#define SHT_HIUSER     0xFFFFFFFF

// Section flags
#define SHF_WRITE      0x1
#define SHF_ALLOC      0x2
#define SHF_EXECINSTR  0x4
#define SHF_MERGE      0x10
#define SHF_STRINGS    0x20
#define SHF_INFO_LINK  0x40
#define SHF_LINK_ORDER 0x80
#define SHF_OS_NONCONFORMING 0x100
#define SHF_GROUP      0x200
#define SHF_TLS        0x400
#define SHF_MASKOS     0x0FF00000
#define SHF_MASKPROC   0xF0000000

// Program header types
#define PT_NULL        0
#define PT_LOAD        1
#define PT_DYNAMIC     2
#define PT_INTERP      3
#define PT_NOTE        4
#define PT_SHLIB       5
#define PT_PHDR        6
#define PT_TLS         7
#define PT_LOOS        0x60000000
#define PT_HIOS        0x6FFFFFFF
#define PT_LOPROC      0x70000000
#define PT_HIPROC      0x7FFFFFFF

// Program header flags
#define PF_X           0x1
#define PF_W           0x2
#define PF_R           0x4
#define PF_MASKOS      0x0FF00000
#define PF_MASKPROC    0xF0000000

// Dynamic entry types
#define DT_NULL        0
#define DT_NEEDED      1
#define DT_PLTRELSZ    2
#define DT_PLTGOT      3
#define DT_HASH        4
#define DT_STRTAB      5
#define DT_SYMTAB      6
#define DT_RELA        7
#define DT_RELASZ      8
#define DT_RELAENT     9
#define DT_STRSZ       10
#define DT_SYMENT      11
#define DT_INIT        12
#define DT_FINI        13
#define DT_SONAME      14
#define DT_RPATH       15
#define DT_SYMBOLIC    16
#define DT_REL         17
#define DT_RELSZ       18
#define DT_RELENT      19
#define DT_PLTREL      20
#define DT_DEBUG       21
#define DT_TEXTREL     22
#define DT_JMPREL      23
#define DT_BIND_NOW    24
#define DT_INIT_ARRAY  25
#define DT_FINI_ARRAY  26
#define DT_INIT_ARRAYSZ 27
#define DT_FINI_ARRAYSZ 28
#define DT_RUNPATH     29
#define DT_FLAGS       30
#define DT_ENCODING    32
#define DT_PREINIT_ARRAY 32
#define DT_PREINIT_ARRAYSZ 33
#define DT_NUM         34
#define DT_LOOS        0x6000000D
#define DT_HIOS        0x6FFFF000
#define DT_LOPROC      0x70000000
#define DT_HIPROC      0x7FFFFFFF

// Symbol binding
#define STB_LOCAL      0
#define STB_GLOBAL     1
#define STB_WEAK       2
#define STB_LOPROC     13
#define STB_HIPROC     15

// Symbol type
#define STT_NOTYPE     0
#define STT_OBJECT     1
#define STT_FUNC       2
#define STT_SECTION    3
#define STT_FILE       4
#define STT_COMMON     5
#define STT_TLS        6
#define STT_LOPROC     13
#define STT_HIPROC     15

// ELF header structure
struct elf32_header {
    uint8_t  e_ident[16];    // ELF identification
    uint16_t e_type;         // Object file type
    uint16_t e_machine;      // Machine type
    uint32_t e_version;      // Object file version
    uint32_t e_entry;        // Entry point address
    uint32_t e_phoff;        // Program header offset
    uint32_t e_shoff;        // Section header offset
    uint32_t e_flags;        // Processor-specific flags
    uint16_t e_ehsize;       // ELF header size
    uint16_t e_phentsize;    // Program header entry size
    uint16_t e_phnum;        // Number of program header entries
    uint16_t e_shentsize;    // Section header entry size
    uint16_t e_shnum;        // Number of section header entries
    uint16_t e_shstrndx;     // Section name string table index
};

// Section header structure
struct elf32_section_header {
    uint32_t sh_name;        // Section name
    uint32_t sh_type;        // Section type
    uint32_t sh_flags;       // Section flags
    uint32_t sh_addr;        // Section virtual address
    uint32_t sh_offset;      // Section file offset
    uint32_t sh_size;        // Section size
    uint32_t sh_link;        // Link to another section
    uint32_t sh_info;        // Additional section information
    uint32_t sh_addralign;   // Section alignment
    uint32_t sh_entsize;     // Entry size if section holds table
};

// Program header structure
struct elf32_program_header {
    uint32_t p_type;         // Segment type
    uint32_t p_offset;       // Segment file offset
    uint32_t p_vaddr;        // Segment virtual address
    uint32_t p_paddr;        // Segment physical address
    uint32_t p_filesz;       // Segment size in file
    uint32_t p_memsz;        // Segment size in memory
    uint32_t p_flags;        // Segment flags
    uint32_t p_align;        // Segment alignment
};

// Symbol table entry
struct elf32_symbol {
    uint32_t st_name;        // Symbol name
    uint32_t st_value;       // Symbol value
    uint32_t st_size;        // Symbol size
    uint8_t  st_info;        // Symbol type and binding
    uint8_t  st_other;       // Symbol visibility
    uint16_t st_shndx;       // Section index
};

// Dynamic entry
struct elf32_dynamic {
    int32_t d_tag;           // Dynamic entry type
    union {
        uint32_t d_val;      // Integer value
        uint32_t d_ptr;      // Address value
    } d_un;
};

// Function declarations
int elf_validate_header(const struct elf32_header* header);
int elf_load_sections(const struct elf32_header* header, void* file_data);
int elf_load_program_headers(const struct elf32_header* header, void* file_data);
int elf_setup_memory_protection(const struct elf32_header* header);
void* elf_get_entry_point(const struct elf32_header* header);

#endif // _ELF_H 