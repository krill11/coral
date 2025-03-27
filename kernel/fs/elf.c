#include "elf.h"
#include "../mm/memory.h"
#include <string.h>

// ELF magic number
#define ELF_MAGIC 0x464C457F  // "\x7FELF"

// Validate ELF header
int elf_validate_header(const struct elf32_header* header) {
    if (!header) return -1;
    
    // Check magic number
    if (*(uint32_t*)header->e_ident != ELF_MAGIC) {
        return -1;
    }
    
    // Check file class (32-bit)
    if (header->e_ident[4] != ELFCLASS32) {
        return -1;
    }
    
    // Check data encoding (little-endian)
    if (header->e_ident[5] != ELFDATA2LSB) {
        return -1;
    }
    
    // Check file type (executable or dynamic)
    if (header->e_type != ET_EXEC && header->e_type != ET_DYN) {
        return -1;
    }
    
    // Check machine type (x86)
    if (header->e_machine != EM_386 && header->e_machine != EM_486) {
        return -1;
    }
    
    // Check version
    if (header->e_version != EV_CURRENT) {
        return -1;
    }
    
    return 0;
}

// Load ELF sections
int elf_load_sections(const struct elf32_header* header, void* file_data) {
    if (!header || !file_data) return -1;
    
    // Find string table section
    struct elf32_section_header* strtab_header = 0;
    for (int i = 0; i < header->e_shnum; i++) {
        struct elf32_section_header* sh = (struct elf32_section_header*)
            ((char*)file_data + header->e_shoff + i * header->e_shentsize);
        if (sh->sh_type == SHT_STRTAB) {
            strtab_header = sh;
            break;
        }
    }
    
    if (!strtab_header) return -1;
    
    // Load sections
    for (int i = 0; i < header->e_shnum; i++) {
        struct elf32_section_header* sh = (struct elf32_section_header*)
            ((char*)file_data + header->e_shoff + i * header->e_shentsize);
            
        // Skip empty sections
        if (sh->sh_size == 0) continue;
        
        // Get section name
        const char* name = (const char*)file_data + strtab_header->sh_offset + sh->sh_name;
        
        // Allocate memory for section
        void* section_addr = kmalloc(sh->sh_size);
        if (!section_addr) return -1;
        
        // Copy section data
        memcpy(section_addr, (char*)file_data + sh->sh_offset, sh->sh_size);
        
        // Map section into memory
        map_page(section_addr, (void*)sh->sh_addr, 
                PAGE_PRESENT | PAGE_RW | PAGE_USER);
    }
    
    return 0;
}

// Load program headers
int elf_load_program_headers(const struct elf32_header* header, void* file_data) {
    if (!header || !file_data) return -1;
    
    // Get program headers
    struct elf32_program_header* program_headers = 
        (struct elf32_program_header*)((char*)file_data + header->e_phoff);
    
    // Load each program header
    for (uint16_t i = 0; i < header->e_phnum; i++) {
        struct elf32_program_header* phdr = &program_headers[i];
        
        // Skip non-loadable segments
        if (phdr->p_type != PT_LOAD) continue;
        
        // Calculate memory protection flags
        uint32_t flags = PAGE_PRESENT | PAGE_USER;
        if (phdr->p_flags & PF_W) flags |= PAGE_RW;
        if (phdr->p_flags & PF_X) flags |= PAGE_RW;
        
        // Map segment into memory
        uint32_t vaddr = phdr->p_vaddr & ~(PAGE_SIZE - 1);
        uint32_t offset = phdr->p_offset & ~(PAGE_SIZE - 1);
        
        for (uint32_t addr = vaddr; 
             addr < vaddr + phdr->p_memsz; 
             addr += PAGE_SIZE) {
            void* page = get_page();
            if (!page) return -1;
            
            map_page(page, (void*)addr, flags);
            
            // Copy segment data
            if (addr < vaddr + phdr->p_filesz) {
                memcpy((void*)addr,
                       (char*)file_data + offset + (addr - vaddr),
                       PAGE_SIZE);
            } else {
                // Zero-fill BSS section
                memset((void*)addr, 0, PAGE_SIZE);
            }
        }
    }
    
    return 0;
}

// Set up memory protection
int elf_setup_memory_protection(const struct elf32_header* header) {
    if (!header) return -1;
    
    // Get program headers
    struct elf32_program_header* program_headers = 
        (struct elf32_program_header*)((char*)header + header->e_phoff);
    
    // Set up protection for each segment
    for (uint16_t i = 0; i < header->e_phnum; i++) {
        struct elf32_program_header* phdr = &program_headers[i];
        
        if (phdr->p_type != PT_LOAD) continue;
        
        // Calculate memory protection flags
        uint32_t flags = PAGE_PRESENT | PAGE_USER;
        if (phdr->p_flags & PF_W) flags |= PAGE_RW;
        if (phdr->p_flags & PF_X) flags |= PAGE_RW;
        
        // Update page protection
        uint32_t vaddr = phdr->p_vaddr & ~(PAGE_SIZE - 1);
        for (uint32_t addr = vaddr; 
             addr < vaddr + phdr->p_memsz; 
             addr += PAGE_SIZE) {
            // Update page protection flags
            // Note: This would require implementing page protection modification
            // in the memory management system
        }
    }
    
    return 0;
}

// Get program entry point
void* elf_get_entry_point(const struct elf32_header* header) {
    if (!header) return 0;
    return (void*)header->e_entry;
} 