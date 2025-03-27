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
    
    // Get section headers
    struct elf32_section_header* section_headers = 
        (struct elf32_section_header*)((char*)file_data + header->e_shoff);
    
    // Get section name string table
    struct elf32_section_header* strtab_header = 
        &section_headers[header->e_shstrndx];
    const char* strtab = (const char*)file_data + strtab_header->sh_offset;
    
    // Load each section
    for (uint16_t i = 0; i < header->e_shnum; i++) {
        struct elf32_section_header* section = &section_headers[i];
        
        // Skip sections that don't need to be loaded
        if (section->sh_type == SHT_NULL || 
            section->sh_type == SHT_NOBITS ||
            !(section->sh_flags & SHF_ALLOC)) {
            continue;
        }
        
        // Allocate memory for section
        void* section_addr = get_page();
        if (!section_addr) return -1;
        
        // Map section into memory
        uint32_t flags = PAGE_PRESENT | PAGE_USER;
        if (section->sh_flags & SHF_WRITE) flags |= PAGE_RW;
        if (section->sh_flags & SHF_EXECINSTR) flags |= PAGE_RW;
        
        map_page(section_addr, (void*)section->sh_addr, flags);
        
        // Copy section data
        if (section->sh_type != SHT_NOBITS) {
            memcpy((void*)section->sh_addr,
                   (char*)file_data + section->sh_offset,
                   section->sh_size);
        }
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